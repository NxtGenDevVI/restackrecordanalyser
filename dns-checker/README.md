# DNS Email Authentication Checker

A production-ready web application for checking DNS email authentication records (SPF, DKIM, DMARC) for any domain. Built for RE:STACK expo usage on iPads.

## Features

- SPF record validation and mechanism checking
- DKIM selector verification (5 common selectors)
- DMARC policy detection
- Touch-optimized interface for iPad
- Reliable DNS-over-HTTPS queries
- Clean, professional RE:STACK branding

## Deployment to GitHub Pages

1. Create a new repository on GitHub
2. Push these files to the repository:
   ```
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPO.git
   git push -u origin main
   ```
3. Enable GitHub Pages in repository settings:
   - Go to Settings > Pages
   - Source: Deploy from a branch
   - Branch: main, folder: / (root)
   - Save

4. Your site will be available at: `https://YOUR-USERNAME.github.io/YOUR-REPO/`

## Local Testing

Simply open `index.html` in a web browser. No build step or server required.

## Technical Details

- Pure HTML, CSS, and JavaScript
- Uses Cloudflare DNS-over-HTTPS API for reliable DNS lookups
- No dependencies or frameworks
- Works offline after initial load (except DNS queries)
- Fully responsive and touch-optimized

## Browser Compatibility

- Safari (iOS/iPadOS)
- Chrome
- Firefox
- Edge

## License

© 2026 RE:STACK. All Rights Reserved.
