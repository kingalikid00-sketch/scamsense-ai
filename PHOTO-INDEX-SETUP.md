# ScamSense Photo Search index setup

The search endpoint compares an uploaded picture's 64-bit perceptual hash with images stored in the ScamSense D1 `photo_index` table. It does not search the entire web and does not identify a person.

## Enable the public image indexer

The scheduled GitHub Action indexes a small batch of openly licensed image files from Wikimedia Commons. It keeps the source page, image URL, title, and license/author attribution in the source label.

1. Generate a long random secret value. Do not put it in source code or send it in chat.
2. In the Cloudflare dashboard, open Workers & Pages → scamsense-ai → Settings → Variables and Secrets. Add a secret named `PHOTO_INDEX_KEY` with that value, then save and deploy the Worker.
3. In GitHub, open this repository → Settings → Secrets and variables → Actions → New repository secret. Name it `PHOTO_INDEX_KEY` and enter the exact same value.
4. Open Actions → ScamSense public photo index → Run workflow.
5. After the first successful run, the search endpoint will report how many public images are indexed. The workflow also runs daily.

## Important

- Only source images with a recognized CC0, CC BY, CC BY-SA, or public-domain license are indexed.
- Wikimedia Commons source pages are retained so users can inspect the original page and attribution.
- The indexer does not scrape private profiles, bypass logins, or collect private images.
- Similarity is a visual-hash match, not proof that two pictures show the same person.
- The current scheduled batch is deliberately small. Increase `MAX_IMAGES_PER_CATEGORY` only after checking Worker limits, Commons API guidance, and D1 usage.
- The Worker already exposes `POST /photo-search` for the app and protected `POST /photo-index` for this indexer.
