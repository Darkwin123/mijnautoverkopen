
const http = require('http');
const fs = require('fs');
const path = require('path');

const server = http.createServer((req, res) => {
  console.log(`Request received for: ${req.url}`);
  
  // Serve index.html for root path
  if (req.url === '/' || req.url === '/index.html') {
    fs.readFile(path.join(__dirname, 'public/index.html'), (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading index.html');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
  } else {
    // Attempt to serve static files from public directory
    fs.readFile(path.join(__dirname, 'public', req.url), (err, data) => {
      if (err) {
        res.writeHead(404);
        res.end('File not found');
        return;
      }
      
      // Set content type based on file extension
      let contentType = 'text/plain';
      const ext = path.extname(req.url);
      if (ext === '.html') contentType = 'text/html';
      if (ext === '.css') contentType = 'text/css';
      if (ext === '.js') contentType = 'text/javascript';
      
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(data);
    });
  }
});

const PORT = 3001;
server.listen(PORT, () => {
  console.log(`Server is definitely running at http://localhost:${PORT}`);
  console.log('Press Ctrl+C to stop the server');
});