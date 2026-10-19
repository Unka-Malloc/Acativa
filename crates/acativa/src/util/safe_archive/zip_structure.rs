//! ZIP transport admission, before either inspection or extraction trusts an index.
//!
//! The ZIP index is not a physical inventory. Reconcile it with every local record,
//! descriptor and the end records, and require each Deflate stream to finish exactly
//! at its advertised boundary. The ZIP crate remains the decoder/CRC authority.

use super::ZipExtractionLimits;
use anyhow::{Result, anyhow, ensure};
use flate2::{Decompress, FlushDecompress, Status};
use std::io::Cursor;

fn field(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(len)
                    .ok_or_else(|| anyhow!("zip_offset_invalid"))?,
        )
        .ok_or_else(|| anyhow!("zip_record_truncated"))
}

fn word(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(field(bytes, offset, 2)?.try_into()?))
}

fn dword(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(field(bytes, offset, 4)?.try_into()?))
}

fn qword(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(field(bytes, offset, 8)?.try_into()?))
}

pub(crate) fn validate_zip_structure(bytes: &[u8], limits: ZipExtractionLimits) -> Result<()> {
    ensure!(
        bytes.len() as u64 <= limits.max_archive_bytes,
        "zip_archive_byte_limit_exceeded"
    );
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    ensure!(
        archive.len() <= limits.max_entries,
        "zip_entry_count_limit_exceeded"
    );
    ensure!(archive.offset() == 0, "zip_unindexed_material");
    let central_start = usize::try_from(archive.central_directory_start())?;
    let mut central = central_start;
    let mut locals = Vec::with_capacity(archive.len());
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let entry = archive.by_index_raw(index)?;
        ensure!(
            entry.central_header_start() == central as u64,
            "zip_index_inconsistent"
        );
        ensure!(
            dword(bytes, central)? == 0x02014b50,
            "zip_index_inconsistent"
        );
        let flags = word(bytes, central + 8)?;
        let method = word(bytes, central + 10)?;
        ensure!(
            flags & 1 == 0 && !entry.encrypted(),
            "zip_encryption_unsupported"
        );
        ensure!(word(bytes, central + 34)? == 0, "zip_multidisk_unsupported");
        let name_len = word(bytes, central + 28)? as usize;
        let extra_len = word(bytes, central + 30)? as usize;
        let comment_len = word(bytes, central + 32)? as usize;
        let name = field(bytes, central + 46, name_len)?;
        ensure!(name == entry.name_raw(), "zip_index_inconsistent");
        central += 46 + name_len + extra_len + comment_len;
        let local = usize::try_from(entry.header_start())?;
        ensure!(
            dword(bytes, local)? == 0x04034b50,
            "zip_local_header_invalid"
        );
        ensure!(
            word(bytes, local + 6)? == flags && word(bytes, local + 8)? == method,
            "zip_local_header_mismatch"
        );
        let local_name_len = word(bytes, local + 26)? as usize;
        let local_extra_len = word(bytes, local + 28)? as usize;
        ensure!(
            field(bytes, local + 30, local_name_len)? == name,
            "zip_local_name_mismatch"
        );
        let data_start = local + 30 + local_name_len + local_extra_len;
        let entry_data_start = entry
            .data_start()
            .ok_or_else(|| anyhow!("zip_local_header_mismatch"))?;
        ensure!(
            entry_data_start == data_start as u64,
            "zip_local_header_mismatch"
        );
        let size = entry.size();
        let compressed = entry.compressed_size();
        ensure!(
            size <= limits.max_file_bytes,
            "zip_file_byte_limit_exceeded"
        );
        total = total
            .checked_add(size)
            .ok_or_else(|| anyhow!("zip_total_byte_count_overflowed"))?;
        ensure!(
            total <= limits.max_total_bytes,
            "zip_total_byte_limit_exceeded"
        );
        let extra = field(bytes, local + 30 + local_name_len, local_extra_len)?;
        let (local_size, local_compressed) = local_sizes(bytes, local, extra)?;
        let checksum = dword(bytes, local + 14)?;
        if flags & 8 == 0 {
            ensure!(
                local_size == size && local_compressed == compressed && checksum == entry.crc32(),
                "zip_local_size_mismatch"
            );
        } else {
            ensure!(
                (local_size == 0 || local_size == size)
                    && (local_compressed == 0 || local_compressed == compressed)
                    && (checksum == 0 || checksum == entry.crc32()),
                "zip_local_size_mismatch"
            );
        }
        let data = field(bytes, data_start, usize::try_from(compressed)?)?;
        let data_end = data_start + data.len();
        ensure!(data_end <= central_start, "zip_member_overlap");
        validate_compressed(data, method, size)?;
        locals.push((
            local,
            data_end,
            flags & 8 != 0,
            entry.crc32(),
            compressed,
            size,
        ));
    }
    locals.sort_unstable_by_key(|entry| entry.0);
    let mut next = 0;
    for (index, &(start, end, descriptor, checksum, compressed, size)) in locals.iter().enumerate()
    {
        ensure!(start == next, "zip_unindexed_material");
        let boundary = locals.get(index + 1).map_or(central_start, |entry| entry.0);
        ensure!(end <= boundary, "zip_member_overlap");
        if descriptor {
            validate_descriptor(
                field(bytes, end, boundary - end)?,
                checksum,
                compressed,
                size,
            )?;
        } else {
            ensure!(end == boundary, "zip_unindexed_material");
        }
        next = boundary;
    }
    ensure!(next == central_start, "zip_unindexed_material");
    validate_end(bytes, central_start, central, archive.len())
}

fn local_sizes(bytes: &[u8], local: usize, extra: &[u8]) -> Result<(u64, u64)> {
    let mut size = u64::from(dword(bytes, local + 22)?);
    let mut compressed = u64::from(dword(bytes, local + 18)?);
    if size != u32::MAX as u64 && compressed != u32::MAX as u64 {
        return Ok((size, compressed));
    }
    let mut offset = 0;
    while offset < extra.len() {
        let tag = word(extra, offset)?;
        let length = word(extra, offset + 2)? as usize;
        let data = field(extra, offset + 4, length)?;
        if tag == 1 {
            let mut position = 0;
            if size == u32::MAX as u64 {
                size = qword(data, position)?;
                position += 8;
            }
            if compressed == u32::MAX as u64 {
                compressed = qword(data, position)?;
            }
            return Ok((size, compressed));
        }
        offset += 4 + length;
    }
    Err(anyhow!("zip_local_zip64_missing"))
}

fn validate_descriptor(bytes: &[u8], checksum: u32, compressed: u64, size: u64) -> Result<()> {
    let offset = match bytes.len() {
        16 | 24 => {
            ensure!(dword(bytes, 0)? == 0x08074b50, "zip_descriptor_invalid");
            4
        }
        12 | 20 => 0,
        _ => return Err(anyhow!("zip_descriptor_invalid")),
    };
    ensure!(dword(bytes, offset)? == checksum, "zip_descriptor_mismatch");
    let (actual_compressed, actual_size) = if bytes.len() - offset == 20 {
        (qword(bytes, offset + 4)?, qword(bytes, offset + 12)?)
    } else {
        (
            u64::from(dword(bytes, offset + 4)?),
            u64::from(dword(bytes, offset + 8)?),
        )
    };
    ensure!(
        actual_compressed == compressed && actual_size == size,
        "zip_descriptor_mismatch"
    );
    Ok(())
}

fn validate_compressed(bytes: &[u8], method: u16, size: u64) -> Result<()> {
    if method == 0 {
        ensure!(bytes.len() as u64 == size, "zip_entry_size_mismatch");
        return Ok(());
    }
    ensure!(method == 8, "zip_compression_unsupported");
    let mut decoder = Decompress::new(false);
    let mut output = [0; 8192];
    loop {
        let before = (decoder.total_in(), decoder.total_out());
        let status = decoder.decompress(
            &bytes[before.0 as usize..],
            &mut output,
            FlushDecompress::None,
        )?;
        ensure!(decoder.total_out() <= size, "zip_entry_size_mismatch");
        if status == Status::StreamEnd {
            ensure!(
                decoder.total_in() == bytes.len() as u64 && decoder.total_out() == size,
                "zip_decoder_completion_mismatch"
            );
            return Ok(());
        }
        ensure!(
            before != (decoder.total_in(), decoder.total_out()),
            "zip_decoder_incomplete"
        );
    }
}

fn validate_end(bytes: &[u8], start: usize, end: usize, count: usize) -> Result<()> {
    let mut eocd = end;
    if dword(bytes, end)? == 0x06064b50 {
        let length = usize::try_from(qword(bytes, end + 4)?)?;
        ensure!(length >= 44, "zip_end_invalid");
        field(bytes, end + 12, length)?;
        ensure!(
            dword(bytes, end + 16)? == 0 && dword(bytes, end + 20)? == 0,
            "zip_multidisk_unsupported"
        );
        ensure!(
            qword(bytes, end + 24)? == count as u64
                && qword(bytes, end + 32)? == count as u64
                && qword(bytes, end + 40)? == (end - start) as u64
                && qword(bytes, end + 48)? == start as u64,
            "zip_end_mismatch"
        );
        let locator = end + 12 + length;
        ensure!(
            dword(bytes, locator)? == 0x07064b50
                && dword(bytes, locator + 4)? == 0
                && qword(bytes, locator + 8)? == end as u64
                && dword(bytes, locator + 16)? == 1,
            "zip_end_mismatch"
        );
        eocd = locator + 20;
    }
    ensure!(dword(bytes, eocd)? == 0x06054b50, "zip_end_invalid");
    ensure!(
        word(bytes, eocd + 4)? == 0 && word(bytes, eocd + 6)? == 0,
        "zip_multidisk_unsupported"
    );
    for offset in [8, 10] {
        let value = word(bytes, eocd + offset)?;
        ensure!(
            value as usize == count || (eocd != end && value == u16::MAX),
            "zip_end_mismatch"
        );
    }
    for (offset, expected) in [(12, end - start), (16, start)] {
        let value = dword(bytes, eocd + offset)?;
        ensure!(
            value as usize == expected || (eocd != end && value == u32::MAX),
            "zip_end_mismatch"
        );
    }
    ensure!(
        eocd + 22 + word(bytes, eocd + 20)? as usize == bytes.len(),
        "zip_trailing_material"
    );
    Ok(())
}
