const express = require('express');
const path = require('path');
const app = express();
const port = 3000;

// Serve static files from the same directory as this script
app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'welcome.html'));
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});
