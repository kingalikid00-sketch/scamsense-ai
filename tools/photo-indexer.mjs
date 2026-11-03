import sharp from "sharp";

const API = "https://commons.wikimedia.org/w/api.php";
const WORKER = (process.env.PHOTO_INDEX_WORKER_URL || "https://scamsense-ai.kingalikid00.workers.dev").replace(/\/$/, "");
const KEY = process.env.PHOTO_INDEX_KEY;
const USER_AGENT = "ScamSensePhotoIndexer/1.0 (public image indexing; contact: scamsense project)";
const MAX_PER_CATEGORY = Math.max(1, Math.min(50, Number(process.env.MAX_IMAGES_PER_CATEGORY || 30)));
const CATEGORIES = ["Category:Portrait photographs", "Category:People by name"];

if (!KEY) throw new Error("PHOTO_INDEX_KEY secret is required.");

function stripHtml(value = "") {
  return String(value).replace(/<[^>]*>/g, " ").replace(/&amp;/g, "&")
    .replace(/&#039;/g, "'").replace(/&quot;/g, '"').replace(/\s+/g, " ").trim();
}
function reusableLicense(meta) {
  const name = stripHtml(meta?.LicenseShortName?.value || "").toLowerCase();
  return /^(cc0|cc by|cc by-sa|public domain|pd)/.test(name);
}
async function api(params) {
  const url = new URL(API);
  for (const [k, v] of Object.entries({ action: "query", format: "json", formatversion: "2", ...params })) url.searchParams.set(k, v);
  const res = await fetch(url, { headers: { "User-Agent": USER_AGENT } });
  if (!res.ok) throw new Error("Wikimedia Commons API returned HTTP " + res.status);
  return res.json();
}
async function hashImage(url) {
  const res = await fetch(url, { headers: { "User-Agent": USER_AGENT } });
  if (!res.ok) throw new Error("image-fetch-" + res.status);
  const input = Buffer.from(await res.arrayBuffer());
  if (input.length > 8 * 1024 * 1024) throw new Error("image-too-large");
  const { data } = await sharp(input, { limitInputPixels: 40000000 })
    .rotate().resize(9, 8, { fit: "fill" }).greyscale().raw().toBuffer({ resolveWithObject: true });
  let bits = "";
  for (let y = 0; y < 8; y++) {
    for (let x = 0; x < 8; x++) bits += data[y * 9 + x] > data[y * 9 + x + 1] ? "1" : "0";
  }
  let hex = "";
  for (let i = 0; i < 64; i += 4) hex += parseInt(bits.slice(i, i + 4), 2).toString(16);
  return hex;
}
async function addToIndex(record) {
  const res = await fetch(WORKER + "/photo-index", {
    method: "POST",
    headers: { "Authorization": "Bearer " + KEY, "Content-Type": "application/json" },
    body: JSON.stringify(record)
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Worker rejected an index record (" + res.status + ")");
}
async function runCategory(category) {
  let continuation = {};
  let processed = 0;
  while (processed < MAX_PER_CATEGORY) {
    const data = await api({
      generator: "categorymembers", gcmtitle: category, gcmtype: "file", gcmnamespace: "6",
      gcmlimit: "20", prop: "imageinfo", iiprop: "url|extmetadata", iiurlwidth: "640",
      ...continuation
    });
    const pages = data.query?.pages || [];
    if (!pages.length) break;
    for (const page of pages) {
      if (processed >= MAX_PER_CATEGORY) break;
      const info = page.imageinfo?.[0];
      if (!info?.thumburl || !reusableLicense(info.extmetadata)) continue;
      try {
        const hash = await hashImage(info.thumburl);
        const license = stripHtml(info.extmetadata?.LicenseShortName?.value || "Open license");
        const author = stripHtml(info.extmetadata?.Artist?.value || "");
        const title = stripHtml(page.title.replace(/^File:/, ""));
        await addToIndex({
          hash,
          imageUrl: info.thumburl,
          pageUrl: info.descriptionurl,
          title: title.slice(0, 220),
          source: ("Wikimedia Commons · " + license + (author ? " · " + author : "")).slice(0, 120)
        });
        processed++;
        console.log("Indexed", title);
      } catch (error) {
        console.log("Skipped one file:", error.message);
      }
    }
    continuation = data.continue || {};
    if (!Object.keys(continuation).length) break;
  }
  return processed;
}

let total = 0;
for (const category of CATEGORIES) {
  try {
    const count = await runCategory(category);
    total += count;
    console.log(category + ": " + count + " indexed");
  } catch (error) {
    console.error(category + " failed:", error.message);
  }
}
console.log("Photo index run complete. New/updated records:", total);
