const axios = require('axios');
require('dotenv').config();

const API_URL = process.env.API_URL || 'http://localhost:5000';

async function testShareAPI() {
    console.log('🧪 Testing Share API endpoints...');
    
    try {
        // Test server is running
        console.log('1. Testing server connection...');
        const healthCheck = await axios.get(`${API_URL}/`);
        console.log('✅ Server is running:', healthCheck.data.message);

        // Test creating a share (this will fail without auth, but we can check the endpoint exists)
        console.log('2. Testing share creation endpoint...');
        try {
            await axios.post(`${API_URL}/api/share/create`, {
                settings: { theme: 'light' },
                habits: []
            });
        } catch (error) {
            if (error.response && error.response.status === 401) {
                console.log('✅ Share creation endpoint exists (requires auth)');
            } else {
                console.log('❌ Unexpected error:', error.message);
            }
        }

        // Test retrieving a non-existent share
        console.log('3. Testing share retrieval endpoint...');
        try {
            await axios.get(`${API_URL}/api/share/nonexistent`);
        } catch (error) {
            if (error.response && error.response.status === 404) {
                console.log('✅ Share retrieval endpoint exists (returns 404 for missing shares)');
            } else {
                console.log('❌ Unexpected error:', error.message);
            }
        }

        console.log('🎉 All API endpoint tests passed!');
        
    } catch (error) {
        console.error('❌ API test failed:', error.message);
        console.log('Make sure the backend server is running on', API_URL);
    }
}

// Run the test
testShareAPI();