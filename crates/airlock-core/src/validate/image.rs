//! Image sanitizing: decode with limits, apply EXIF orientation, re-encode.
//! Re-encoding drops every metadata chunk (EXIF, GPS, XMP, ICC text).

use std::io::Cursor;

use image::codecs::jpeg::JpegEncoder;
use image::codecs::webp::WebPEncoder;
use image::{DynamicImage, ImageDecoder, ImageFormat, ImageReader, Limits};

use crate::validate::sniff;
use crate::{Error, Result};

pub const MAX_DIMENSION: u32 = 16_384;
pub const MAX_ALLOC: u64 = 512 * 1024 * 1024;

fn ierr(e: impl std::fmt::Display) -> Error {
    Error::Image(e.to_string())
}

/// Returns `(mime, sanitized bytes)`. The output format matches the input.
pub fn sanitize_image(bytes: &[u8]) -> Result<(&'static str, Vec<u8>)> {
    let mime = sniff::image_mime(bytes).ok_or_else(|| Error::Image("not a png, jpeg or webp".into()))?;
    let format = match mime {
        "image/png" => ImageFormat::Png,
        "image/jpeg" => ImageFormat::Jpeg,
        _ => ImageFormat::WebP,
    };
    let mut reader = ImageReader::new(Cursor::new(bytes));
    reader.set_format(format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(MAX_ALLOC);
    reader.limits(limits);
    let mut decoder = reader.into_decoder().map_err(ierr)?;
    let orientation = decoder.orientation().map_err(ierr)?;
    let mut img = DynamicImage::from_decoder(decoder).map_err(ierr)?;
    img.apply_orientation(orientation);

    let mut out = Vec::new();
    match format {
        ImageFormat::Png => img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png).map_err(ierr)?,
        ImageFormat::Jpeg => DynamicImage::ImageRgb8(img.to_rgb8())
            .write_with_encoder(JpegEncoder::new_with_quality(&mut out, 90))
            .map_err(ierr)?,
        _ => DynamicImage::ImageRgba8(img.to_rgba8())
            .write_with_encoder(WebPEncoder::new_lossless(&mut out))
            .map_err(ierr)?,
    }
    Ok((mime, out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Rgb, RgbImage};

    fn png_with_text_chunk() -> Vec<u8> {
        let img = DynamicImage::ImageRgb8(RgbImage::from_pixel(4, 3, Rgb([200, 10, 10])));
        let mut png = Vec::new();
        img.write_to(&mut Cursor::new(&mut png), ImageFormat::Png).unwrap();
        // Splice a tEXt chunk with a fake GPS comment right after IHDR.
        let data = b"Comment\0gps=51.5,-0.1";
        let mut chunk = (data.len() as u32).to_be_bytes().to_vec();
        chunk.extend_from_slice(b"tEXt");
        chunk.extend_from_slice(data);
        let crc = crc32(&chunk[4..]);
        chunk.extend_from_slice(&crc.to_be_bytes());
        let ihdr_end = 8 + 4 + 4 + 13 + 4;
        let mut out = png[..ihdr_end].to_vec();
        out.extend_from_slice(&chunk);
        out.extend_from_slice(&png[ihdr_end..]);
        out
    }

    fn crc32(b: &[u8]) -> u32 {
        let mut c = 0xffff_ffffu32;
        for &x in b {
            c ^= x as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            }
        }
        !c
    }

    #[test]
    fn strips_metadata_and_keeps_pixels() {
        let dirty = png_with_text_chunk();
        assert!(dirty.windows(3).any(|w| w == b"gps"));
        let (mime, clean) = sanitize_image(&dirty).unwrap();
        assert_eq!(mime, "image/png");
        assert!(!clean.windows(3).any(|w| w == b"gps"));
        let back = image::load_from_memory(&clean).unwrap().to_rgb8();
        assert_eq!(back.dimensions(), (4, 3));
        assert_eq!(back.get_pixel(0, 0), &Rgb([200, 10, 10]));
    }

    #[test]
    fn rejects_non_images() {
        assert!(sanitize_image(b"GIF89a....").is_err());
        assert!(sanitize_image(b"\x89PNG\r\n\x1a\ngarbage").is_err());
    }
}
