# Google Script API

A Node.js API that integrates with Google Sheets and Google Drive to manage medication data and orders.

## Features

- Google Sheets Integration
- Google Drive Integration
- OAuth2 Authentication
- Medication Data Management
- Order Management
- Folder Structure Management

## Prerequisites

- Node.js (v14 or higher)
- Google Cloud Platform Account
- OAuth2 Credentials

## Installation

1. Clone the repository:

```bash
git clone https://github.com/ADIMYY/Google_Script.git
cd Google_Script
```

2. Install dependencies:

```bash
npm install
```

3. Create a `config.env` file in the root directory with the following variables:

```env
CLIENT_ID=your_client_id
CLIENT_SECRET=your_client_secret
REDIRECT_URI=your_redirect_uri
REFRESH_TOKEN=your_refresh_token
PORT=3000
```

## API Endpoints

### Authentication

- `GET /auth` - Initiates OAuth2 authentication flow
- `GET /oauth2callback` - OAuth2 callback endpoint

### Sheet Management

- `POST /api` with action:

  - `createsheet` - Create a new sheet
  - `createordersheet` - Create a new order sheet
  - `deletesheet` - Delete a sheet
  - `storemedication` - Store medication data
  - `updatemedication` - Update medication data
  - `storeorder` - Store order data

- `GET /api` with action:
  - `listsheets` - List all sheets
  - `retrieve` - Retrieve medication data
  - `listordersheets` - List order sheets

## Folder Structure

The API creates and manages the following folder structure in Google Drive:

```
NAQQAS/
├── SHEETS_FOLDER/
│   └── [user_email]/
└── ORDER_FOLDER/
    └── [user_email]/
```

## Usage

1. Start the server:

```bash
node app.js
```

2. Visit `http://localhost:3000/auth` to authenticate with Google
3. After authentication, you can use the API endpoints to manage your sheets and data

## Deployment

### Local Deployment

1. Start the server:

```bash
node app.js
```

2. Visit `http://localhost:3000/auth` to authenticate with Google

### Vercel Deployment

This project is configured for easy deployment on Vercel:

1. Create a Vercel account at [vercel.com](https://vercel.com) if you don't have one
2. Install the Vercel CLI:

```bash
npm install -g vercel
```

3. Deploy to Vercel:

```bash
vercel
```

4. Set up environment variables in the Vercel dashboard:

   - Go to your project settings
   - Navigate to the "Environment Variables" section
   - Add the following variables:
     - `CLIENT_ID`
     - `CLIENT_SECRET`
     - `REDIRECT_URI` (set this to your Vercel deployment URL + `/oauth2callback`)
     - `REFRESH_TOKEN`

5. Update your Google Cloud Console OAuth 2.0 configuration:
   - Add your Vercel deployment URL to the authorized redirect URIs
   - Add your Vercel deployment URL to the authorized JavaScript origins

## Error Handling

The API includes comprehensive error handling for:

- Authentication failures
- Missing required fields
- Sheet access issues
- Invalid actions
- Token refresh failures

## Security

- OAuth2 authentication
- Environment variable configuration
- Secure token management
- User-specific folder access

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
