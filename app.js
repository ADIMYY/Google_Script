import express from 'express';
import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import fetch from 'node-fetch';
import fs from 'fs';

// Get the directory name of the current module
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
dotenv.config({ path: __dirname + '/config.env' });

const app = express();
app.use(bodyParser.json());
const PORT = process.env.PORT || 3000;

// === Constants ===
const FOLDER_NAMES = {
    ROOT_FOLDER: "NAQQAS",
    SHEETS_FOLDER: "SHEETS_FOLDER",
    ORDER_FOLDER: "ORDER_FOLDER",
};

const FOLDER_TYPES = {
    SHEETS: "SHEETS_FOLDER",
    ORDER: "ORDER_FOLDER"
};

const ERROR_MESSAGES = {
    MISSING_REQUIRED_FIELD: (field) => `Missing required field: ${field}`,
    SHEET_NOT_FOUND: "Sheet not found or you do not have permission to access it.",
    INVALID_ACTION: "Invalid action.",
    REQUEST_BODY_MISSING: "Request body is missing.",
    MEDICATION_NOT_FOUND: "Medication not found in the sheet.",
    SHEET_NAME_REQUIRED: "Sheet name is required and must be a string.",
    SHEET_ID_REQUIRED: "Sheet ID is required.",
    SHEET_ID_MED_NAME_QUANTITY_REQUIRED: "Sheet ID, medication name, and quantity are required.",
    AUTHENTICATION_FAILED: "Authentication failed.",
    TOKEN_REFRESH_FAILED: "Failed to refresh access token."
};

// === Authentication Setup ===
// Create an OAuth2 client
function getAuthClient() {
    try {
        const oauth2Client = new OAuth2Client(
            process.env.CLIENT_ID,
            process.env.CLIENT_SECRET,
            process.env.REDIRECT_URI
        );
        if (process.env.REFRESH_TOKEN) {
            console.log('Setting refresh token:', process.env.REFRESH_TOKEN);
            oauth2Client.setCredentials({
                refresh_token: process.env.REFRESH_TOKEN
            });
            console.log('Credentials after setting:', oauth2Client.credentials);
        } else {
            console.log('No REFRESH_TOKEN found in environment variables.');
        }
        return oauth2Client;
    } catch (error) {
        console.error('Error creating auth client:', error);
        throw new Error(ERROR_MESSAGES.AUTHENTICATION_FAILED);
    }
}

// Initialize Google API clients
function getGoogleClients(auth) {
    try {
        const drive = google.drive({ version: 'v3', auth });
        const sheets = google.sheets({ version: 'v4', auth });
        return { drive, sheets };
    } catch (error) {
        console.error('Error initializing Google clients:', error);
        throw new Error(ERROR_MESSAGES.AUTHENTICATION_FAILED);
    }
}

// Refresh token if needed
async function refreshTokenIfNeeded(auth) {
    try {
        console.log('Current auth.credentials:', auth.credentials);
        let credentials = auth.credentials || {};
        
        const preservedRefreshToken = credentials.refresh_token || process.env.REFRESH_TOKEN;
        
        if (!credentials.access_token || 
            (credentials.expiry_date && credentials.expiry_date <= Date.now() + 60000)) {
            if (!preservedRefreshToken) {
                throw new Error('No refresh token available. Please re-authenticate via /auth.');
            }
            
            console.log('Setting credentials before refresh:', preservedRefreshToken);
            auth.setCredentials({ refresh_token: preservedRefreshToken });
            credentials = auth.credentials || {};
            
            console.log('Credentials before refresh:', auth.credentials);
            console.log('Attempting to refresh token with refresh_token:', preservedRefreshToken);
            
            await auth.refreshAccessToken();
            
            let tokens = auth.credentials;
            console.log('Tokens received from refresh:', tokens);
            console.log('Credentials after refresh (before set):', auth.credentials);
            
            if (!tokens) {
                tokens = {
                    access_token: auth.credentials?.access_token,
                    scope: auth.credentials?.scope,
                    token_type: auth.credentials?.token_type,
                    id_token: auth.credentials?.id_token,
                    refresh_token: preservedRefreshToken,
                    expiry_date: auth.credentials?.expiry_date
                };
            }
            
            auth.setCredentials(tokens);
            credentials = auth.credentials || {};
            console.log('Credentials after setting tokens:', auth.credentials);
            
            if (!credentials.refresh_token && preservedRefreshToken) {
                console.log('Restoring refresh_token after refresh:', preservedRefreshToken);
                tokens.refresh_token = preservedRefreshToken;
                auth.setCredentials(tokens);
                credentials = auth.credentials || {};
            }
            
            if (tokens.refresh_token && tokens.refresh_token !== process.env.REFRESH_TOKEN) {
                let envContent = '';
                try {
                    envContent = fs.readFileSync(__dirname + '/config.env', 'utf8');
                } catch (error) {
                    console.error('Error reading .env file:', error);
                }
                if (envContent.includes('REFRESH_TOKEN=')) {
                    envContent = envContent.replace(
                        /REFRESH_TOKEN=.*/,
                        `REFRESH_TOKEN=${tokens.refresh_token}`
                    );
                } else {
                    envContent += `\nREFRESH_TOKEN=${tokens.refresh_token}`;
                }
                try {
                    fs.writeFileSync(__dirname + '/config.env', envContent);
                } catch (error) {
                    console.error('Error writing to .env file:', error);
                }
                process.env.REFRESH_TOKEN = tokens.refresh_token;
            }
            console.log('Token refreshed successfully:', tokens);
            return true;
        }
        return false;
    } catch (error) {
        console.error('Error refreshing token:', error);
        if (preservedRefreshToken && (!auth.credentials || !auth.credentials.refresh_token)) {
            console.log('Restoring refresh token after failure:', preservedRefreshToken);
            auth.setCredentials({ refresh_token: preservedRefreshToken });
        }
        throw new Error(ERROR_MESSAGES.TOKEN_REFRESH_FAILED);
    }
}

// === OAuth2 Authorization Flow ===
// Generate authorization URL
app.get('/auth', (req, res) => {
    const oauth2Client = getAuthClient();
    const scopes = [
        'https://www.googleapis.com/auth/drive',
        'https://www.googleapis.com/auth/spreadsheets',
        'https://www.googleapis.com/auth/userinfo.email'
    ];
    
    const authUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: scopes,
        prompt: 'consent'
    });
    
    res.redirect(authUrl);
});

// OAuth2 callback
app.get('/oauth2callback', async (req, res) => {
    try {
        const oauth2Client = getAuthClient();
        const { code } = req.query;
        
        if (!code) {
            throw new Error('Authorization code is missing');
        }
        
        const { tokens } = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);

        // Get and store the user email
        try {
            const userEmail = await getUserEmail(oauth2Client);
            console.log(`Authenticated user: ${userEmail}`);
        } catch (error) {
            console.error('Could not retrieve user email:', error);
        }
        
        if (tokens.refresh_token) {
            let envContent = '';
            try {
                envContent = fs.readFileSync(__dirname + '/config.env', 'utf8');
            } catch (error) {
                console.error('Error reading .env file:', error);
            }
            
            if (envContent.includes('REFRESH_TOKEN=')) {
                envContent = envContent.replace(
                    /REFRESH_TOKEN=.*/,
                    `REFRESH_TOKEN=${tokens.refresh_token}`
                );
            } else {
                envContent += `\nREFRESH_TOKEN=${tokens.refresh_token}`;
            }
            
            try {
                fs.writeFileSync(__dirname + '/config.env', envContent);
            } catch (error) {
                console.error('Error writing to .env file:', error);
            }
            
            process.env.REFRESH_TOKEN = tokens.refresh_token;
        }
        
        res.send('Authentication successful! You can close this window and return to the application.');
    } catch (error) {
        console.error('Error in OAuth callback:', error);
        res.status(500).send(`Authentication failed: ${error.message}`);
    }
});

// === Folder Management ===
async function getOrCreateUserFolder(auth, folderName) {
    try {
        await refreshTokenIfNeeded(auth);
        
        const { drive } = getGoogleClients(auth);
        
        const response = await drive.files.list({
            q: `name='${folderName}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
            fields: 'files(id, name)'
        });
        
        const folders = response.data.files;
        
        if (folders && folders.length > 0) {
            return folders[0].id;
        } else {
            const fileMetadata = {
                name: folderName,
                mimeType: 'application/vnd.google-apps.folder'
            };
            
            const folder = await drive.files.create({
                resource: fileMetadata,
                fields: 'id'
            });
            
            return folder.data.id;
        }
    } catch (error) {
        console.error('Error in getOrCreateUserFolder:', error);
        throw error;
    }
}

async function getOrCreateSubFolder(auth, parentFolderId, subFolderName) {
    const { drive } = getGoogleClients(auth);
    
    const response = await drive.files.list({
        q: `name='${subFolderName}' and '${parentFolderId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false`,
        fields: 'files(id, name)'
    });
    
    const folders = response.data.files;
    
    if (folders && folders.length > 0) {
        return folders[0].id;
    } else {
        const fileMetadata = {
            name: subFolderName,
            parents: [parentFolderId],
            mimeType: 'application/vnd.google-apps.folder'
        };
        
        const folder = await drive.files.create({
            resource: fileMetadata,
            fields: 'id'
        });
        
        return folder.data.id;
    }
}

async function createFolderStructure(auth, userEmail, folderType = FOLDER_TYPES.SHEETS) {
    try {
        const rootFolderId = await getOrCreateUserFolder(auth, FOLDER_NAMES.ROOT_FOLDER);
        const targetFolderName = folderType === FOLDER_TYPES.ORDER ? FOLDER_NAMES.ORDER_FOLDER : FOLDER_NAMES.SHEETS_FOLDER;
        const targetFolderId = await getOrCreateSubFolder(auth, rootFolderId, targetFolderName);
        const userFolderId = await getOrCreateSubFolder(auth, targetFolderId, userEmail);
        
        return {
            rootFolderId: rootFolderId,
            targetFolderId: targetFolderId,
            userFolderId: userFolderId,
        };
    } catch (error) {
        console.error('Error creating folder structure:', error);
        throw error;
    }
}

// === Get User Email from OAuth Token ===
async function getUserEmail(auth) {
    try {
        if (!auth || !auth.credentials) {
            throw new Error(ERROR_MESSAGES.AUTHENTICATION_FAILED);
        }

        const response = await fetch('https://www.googleapis.com/oauth2/v3/tokeninfo',
            {
                headers: {
                    'Authorization': `Bearer ${auth.credentials.access_token}`
                }
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (!data.email) {
            throw new Error(ERROR_MESSAGES.AUTHENTICATION_FAILED);
        }
        
        return data.email;
    } catch (error) {
        console.error('Error validating token:', error);
        throw new Error(ERROR_MESSAGES.AUTHENTICATION_FAILED);
    }
}

// === Logging ===
async function logEvent(auth, message, type = "INFO") {
    const timestamp = new Date().toISOString();
    console.log(`[${type}] ${timestamp}: ${message}`);
    
    try {
        const logsFolder = await getOrCreateUserFolder(auth, "Logs");
        
        const { drive } = getGoogleClients(auth);
        await drive.files.create({
            resource: {
                name: `${timestamp}_log.txt`,
                parents: [logsFolder],
                mimeType: 'text/plain'
            },
            media: {
                mimeType: 'text/plain',
                body: `[${type}] ${message}`
            }
        });
    } catch (error) {
        console.error('Error logging to Drive:', error);
    }
}

// === Sheet Validation ===
// Modified validateSheetAccess function
async function validateSheetAccess(auth, sheetId, userEmail, folderType = FOLDER_TYPES.SHEETS) {
    if (!sheetId) {
        throw new Error(ERROR_MESSAGES.SHEET_ID_REQUIRED);
    }
    
    try {
        const { drive } = getGoogleClients(auth);
        
        const rootFolderId = await getOrCreateUserFolder(auth, FOLDER_NAMES.ROOT_FOLDER);
        const targetFolderName = folderType === FOLDER_TYPES.ORDER ? FOLDER_NAMES.ORDER_FOLDER : FOLDER_NAMES.SHEETS_FOLDER;
        const targetFolderId = await getOrCreateSubFolder(auth, rootFolderId, targetFolderName);
        const userFolderId = await getOrCreateSubFolder(auth, targetFolderId, userEmail);
        
        // Correct query format without spaces around operators
        const query = `'${userFolderId}' in parents and id='${sheetId}' and mimeType='application/vnd.google-apps.spreadsheet' and trashed=false`;
        
        const response = await drive.files.list({
            q: query,
            fields: 'files(id, name)'
        });
        
        if (!response.data.files || response.data.files.length === 0) {
            throw new Error(ERROR_MESSAGES.SHEET_NOT_FOUND);
        }
        
        return true;
    } catch (error) {
        console.error('Error validating sheet access:', error.message);
        if (error.errors) {
            console.error('Detailed errors:', JSON.stringify(error.errors));
        }
        throw error;
    }
}

// === Spreadsheet Management ===
async function createUserSheet(auth, sheetName, folderType = FOLDER_TYPES.SHEETS) {
    if (!sheetName || typeof sheetName !== "string") {
        throw new Error(ERROR_MESSAGES.SHEET_NAME_REQUIRED);
    }
    
    try {
        const userEmail = await getUserEmail(auth);
        const folderStructure = await createFolderStructure(auth, userEmail, folderType);
        
        const { sheets, drive } = getGoogleClients(auth);
        
        const spreadsheet = await sheets.spreadsheets.create({
            resource: {
                properties: {
                    title: sheetName
                },
                sheets: [
                    {
                        properties: {
                            title: 'Sheet1'
                        }
                    }
                ]
            }
        });
        
        const spreadsheetId = spreadsheet.data.spreadsheetId;
        
        await sheets.spreadsheets.values.update({
            spreadsheetId,
            range: 'Sheet1!A1:C1',
            valueInputOption: 'RAW',
            resource: {
                values: [["Medication Name", "Quantity", "Timestamp"]]
            }
        });
        
        await drive.files.update({
            fileId: spreadsheetId,
            addParents: folderStructure.userFolderId,
            removeParents: 'root'
        });
        
        return spreadsheetId;
    } catch (error) {
        console.error('Error creating user sheet:', error);
        throw error;
    }
}

async function createOrderSheet(auth, sheetName = "Orders", folderType = FOLDER_TYPES.ORDER) {
    try {
        const userEmail = await getUserEmail(auth);
        const folderStructure = await createFolderStructure(auth, userEmail, folderType);
        
        const { drive, sheets } = getGoogleClients(auth);
        
        const response = await drive.files.list({
            q: `name='${sheetName}' and '${folderStructure.userFolderId}' in parents and mimeType='application/vnd.google-apps.spreadsheet' and trashed=false`,
            fields: 'files(id, name)'
        });
        
        if (response.data.files && response.data.files.length > 0) {
            return response.data.files[0].id;
        }
        
        const spreadsheet = await sheets.spreadsheets.create({
            resource: {
                properties: {
                    title: sheetName
                }
            }
        });
        
        const spreadsheetId = spreadsheet.data.spreadsheetId;
        
        await sheets.spreadsheets.values.update({
            spreadsheetId,
            range: 'Sheet1!A1:E1',
            valueInputOption: 'RAW',
            resource: {
                values: [["Medication Name", "Quantity", "Timestamp"]]
            }
        });
        
        await drive.files.update({
            fileId: spreadsheetId,
            addParents: folderStructure.userFolderId,
            removeParents: 'root'
        });
        
        return spreadsheetId;
    } catch (error) {
        console.error('Error creating order sheet:', error);
        throw error;
    }
}

async function storeOrder(auth, sheetId, medications, date = new Date(), folderType = FOLDER_TYPES.ORDER) {
    if (!sheetId || !medications) {
        throw new Error(ERROR_MESSAGES.SHEET_ID_MEDICATIONS_REQUIRED);
    }
    
    try {
        const userEmail = await getUserEmail(auth);
        await validateSheetAccess(auth, sheetId, userEmail, folderType);
        
        const { sheets } = getGoogleClients(auth);
        const timestamp = date instanceof Date ? date.toISOString() : new Date().toISOString();
        
        sheets.spreadsheets.values.append({
            spreadsheetId: sheetId,
            range: 'Sheet1',
            valueInputOption: 'RAW',
            insertDataOption: 'INSERT_ROWS',
            resource: {
                values: [medications.map(med => [med.name, med.quantity, timestamp])]
            }
        });
        
        return true;
    } catch (error) {
        console.error('Error storing order:', error);
        throw error;
    }
}

async function listUserSheets(auth, folderType = FOLDER_TYPES.SHEETS) {
    try {
        const userEmail = await getUserEmail(auth);
        await logEvent(auth, `Listing sheets for user ${userEmail} in folder type: ${folderType}`, "INFO");
        
        const folderStructure = await createFolderStructure(auth, userEmail, folderType);
        console.log('Folder structure:', folderStructure); // Debug log
        
        const { drive } = getGoogleClients(auth);
        const response = await drive.files.list({
            q: `'${folderStructure.userFolderId}' in parents and mimeType='application/vnd.google-apps.spreadsheet' and trashed=false`,
            fields: 'files(id, name)'
        });
        
        const sheets = response.data.files || [];
        await logEvent(auth, `Found ${sheets.length} sheets in folder type: ${folderType}`, "INFO");
        
        return sheets.map(file => ({
            id: file.id,
            name: file.name
        }));
    } catch (error) {
        console.error('Error listing user sheets:', error);
        throw error;
    }
}

async function deleteSheet(auth, sheetId, folderType = FOLDER_TYPES.SHEETS) {
    if (!sheetId) {
        throw new Error(ERROR_MESSAGES.SHEET_ID_REQUIRED);
    }
    
    try {
        const userEmail = await getUserEmail(auth);
        await validateSheetAccess(auth, sheetId, userEmail, folderType);
        
        const { drive } = getGoogleClients(auth);
        
        drive.files.update({
            fileId: sheetId,
            resource: {
                trashed: true
            }
        });
        
        return true;
    } catch (error) {
        console.error('Error deleting sheet:', error);
        throw error;
    }
}

async function updateMedicationData(auth, sheetId, medicationName, newQuantity = null, newName = null, folderType = FOLDER_TYPES.SHEETS) {
    try {
        const userEmail = await getUserEmail(auth);
        await validateSheetAccess(auth, sheetId, userEmail, folderType);
        
        const { sheets } = getGoogleClients(auth);
        
        const response = await sheets.spreadsheets.values.get({
            spreadsheetId: sheetId,
            range: 'Sheet1'
        });
        
        const data = response.data.values || [];
        if (data.length <= 1) {
            throw new Error(ERROR_MESSAGES.MEDICATION_NOT_FOUND);
        }
        
        let updated = false;
        let rowIndex = -1;
        
        for (let i = 1; i < data.length; i++) {
            if (data[i][0].toString().trim().toLowerCase() === medicationName.trim().toLowerCase()) {
                rowIndex = i + 1;
                updated = true;
                break;
            }
        }
        
        if (!updated) {
            throw new Error(ERROR_MESSAGES.MEDICATION_NOT_FOUND);
        }
        
        const updatedName = newName === null ? data[rowIndex - 1][0] : newName;
        const updatedQuantity = newQuantity === null ? data[rowIndex - 1][1] : newQuantity;
        const timestamp = new Date().toISOString();
        
        sheets.spreadsheets.values.update({
            spreadsheetId: sheetId,
            range: `Sheet1!A${rowIndex}:C${rowIndex}`,
            valueInputOption: 'RAW',
            resource: {
                values: [[updatedName, updatedQuantity, timestamp]]
            }
        });
        
        return true;
    } catch (error) {
        console.error('Error updating medication data:', error);
        throw error;
    }
}

async function retrieveMedicationData(auth, sheetId, medicationName = null, folderType = FOLDER_TYPES.SHEETS) {
    if (!sheetId) {
        throw new Error(ERROR_MESSAGES.SHEET_ID_REQUIRED);
    }
    
    try {
        const userEmail = await getUserEmail(auth);
        await validateSheetAccess(auth, sheetId, userEmail, folderType);
        
        const { sheets } = getGoogleClients(auth);
        
        const response = await sheets.spreadsheets.values.get({
            spreadsheetId: sheetId,
            range: 'Sheet1'
        });
        
        const data = response.data.values || [];
        if (data.length <= 1) {
            return [];
        }
        
        const result = data.slice(1).map(row => ({
            medicationName: row[0],
            quantity: row[1],
            timestamp: row[2]
        }));
        
        if (medicationName) {
            return result.filter(item => 
                item.medicationName.toString().trim().toLowerCase() === medicationName.trim().toLowerCase()
            );
        }
        
        return result;
    } catch (error) {
        console.error('Error retrieving medication data:', error);
        throw error;
    }
}

async function storeMedicationData(auth, sheetId, medicationName, quantity, date = new Date(), folderType = FOLDER_TYPES.SHEETS) {
    if (!sheetId || !medicationName || !quantity) {
        throw new Error(ERROR_MESSAGES.SHEET_ID_MED_NAME_QUANTITY_REQUIRED);
    }
    
    try {
        const userEmail = await getUserEmail(auth);
        await validateSheetAccess(auth, sheetId, userEmail, folderType);
        
        const { sheets } = getGoogleClients(auth);
        const timestamp = date instanceof Date ? date.toISOString() : new Date().toISOString();
        
        sheets.spreadsheets.values.append({
            spreadsheetId: sheetId,
            range: 'Sheet1',
            valueInputOption: 'RAW',
            insertDataOption: 'INSERT_ROWS',
            resource: {
                values: [[medicationName, quantity, timestamp]]
            }
        });
        
        return true;
    } catch (error) {
        console.error('Error storing medication data:', error);
        throw error;
    }
}

// === Input Validation ===
function validateInput(data, requiredFields) {
    requiredFields.forEach(field => {
        if (!data[field]) {
            throw new Error(ERROR_MESSAGES.MISSING_REQUIRED_FIELD(field));
        }
    });
}

// === API Endpoints ===
app.post('/api', async (req, res) => {
    let auth;
    try {
        auth = getAuthClient();
        
        await refreshTokenIfNeeded(auth);
        
        if (!req.body) {
            throw new Error(ERROR_MESSAGES.REQUEST_BODY_MISSING);
        }
        
        validateInput(req.body, ["action"]);
        const action = req.body.action;
        
        switch (action) {
            case "createsheet":
                validateInput(req.body, ["sheetName"]);
                const folderType = req.body.folderType || FOLDER_TYPES.SHEETS;
                const sheetId = await createUserSheet(auth, req.body.sheetName, folderType);
                return res.json({ success: true, data: { sheetId } });
                
            case "createordersheet":
                validateInput(req.body, ["sheetName"]);
                const orderSheetId = await createOrderSheet(auth, req.body.sheetName, req.body.folderType);
                return res.json({ success: true, data: { sheetId: orderSheetId } });
                
            case "storeorder":
                validateInput(req.body, ["sheetId", "medications"]);
                const storeResult = await storeOrder(
                    auth,
                    req.body.sheetId, 
                    req.body.medications,
                    req.body.date, 
                    req.body.folderType
                );
                return res.json({ success: true, data: { result: storeResult } });
                
            case "deletesheet":
                validateInput(req.body, ["sheetId"]);
                const deleteResult = await deleteSheet(auth, req.body.sheetId, req.body.folderType);
                return res.json({ success: true, data: { result: deleteResult } });
                
            case "updatemedication":
                validateInput(req.body, ["sheetId", "medicationName"]);
                const updateResult = await updateMedicationData(
                    auth,
                    req.body.sheetId, 
                    req.body.medicationName, 
                    req.body.newQuantity, 
                    req.body.newName, 
                    req.body.folderType
                );
                return res.json({ success: true, data: { result: updateResult } });
                
            case "storemedication":
                validateInput(req.body, ["sheetId", "medicationName", "quantity"]);
                const medicationResult = await storeMedicationData(
                    auth,
                    req.body.sheetId, 
                    req.body.medicationName, 
                    req.body.quantity, 
                    req.body.date, 
                    req.body.folderType
                );
                return res.json({ success: true, data: { result: medicationResult } });
                
            default:
                throw new Error(ERROR_MESSAGES.INVALID_ACTION);
        }
    } catch (error) {
        console.error('API error:', error);
        if (auth) {
            await logEvent(auth, error.toString(), "ERROR");
        }
        return res.status(400).json({ success: false, error: error.toString() });
    }
});

app.get('/api', async (req, res) => {
    let auth;
    try {
        auth = getAuthClient();
        
        await refreshTokenIfNeeded(auth);
        
        const action = req.query.action;
        const sheetId = req.query.sheetId;
        const medicationName = req.query.medicationName;
        
        switch (action) {
            case "listsheets":
                const folderType = req.query.folderType || FOLDER_TYPES.SHEETS;
                await logEvent(auth, `GET request for listsheets with folderType: ${folderType}`, "INFO");
                const sheets = await listUserSheets(auth, folderType);
                return res.json({ success: true, data: { sheets } });
                
            case "retrieve":
                validateInput({ sheetId }, ["sheetId"]);
                const data = await retrieveMedicationData(auth, sheetId, medicationName, req.query.folderType);
                return res.json({ success: true, data: { data } });
                
            case "listordersheets":
                const orderSheets = await listUserSheets(auth, FOLDER_TYPES.ORDER);
                return res.json({ success: true, data: { sheets: orderSheets } });
                
            default:
                throw new Error(ERROR_MESSAGES.INVALID_ACTION);
        }
    } catch (error) {
        console.error('API error:', error);
        if (auth) {
            await logEvent(auth, error.toString(), "ERROR");
        }
        return res.status(400).json({ success: false, error: error.toString() });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`To authenticate, visit: http://localhost:${PORT}/auth`);
});

export default app;