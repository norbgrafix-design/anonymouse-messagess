const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const fs = require("fs");
const path = require("path");
const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(__dirname));
app.use(session({ secret: "secretkey", resave: false, saveUninitialized: true }));

// Database
const db = new sqlite3.Database("./database.db");
db.run(`CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`);
db.run(`CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  message TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Serve main page
app.get("/", (req,res) => res.sendFile(__dirname + "/index.html"));

// Register
app.post("/register", async (req,res) => {
  const { username, password } = req.body;
  if(!username || !password) return res.send("Fill all fields");
  const hash = await bcrypt.hash(password,10);
  db.run("INSERT INTO users (username,password) VALUES (?,?)", [username,hash], function(err){
    if(err) return res.send("Username already taken");
    req.session.userId = this.lastID;
    res.redirect(`/user`);
  });
});

// Login
app.post("/login", (req,res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username=?", [username], async (err,user) => {
    if(!user) return res.send("Invalid username");
    const match = await bcrypt.compare(password, user.password);
    if(match){ req.session.userId = user.id; res.redirect("/user"); }
    else res.send("Wrong password");
  });
});

// User dashboard
app.get("/user", (req,res) => {
  if(!req.session.userId) return res.redirect("/");
  db.get("SELECT * FROM users WHERE id=?", [req.session.userId], (err,user) => {
    if(!user) return res.redirect("/");
    const filePath = path.join(__dirname,"index.html");
    fs.readFile(filePath,"utf8",(err,html)=>{
      if(err) return res.send("Error");
      html = html.replace(/__USERNAME__/g, user.username);
      // Fetch messages
      db.all("SELECT * FROM messages WHERE user_id=? ORDER BY id DESC LIMIT 50",[user.id], (err,msgs)=>{
        let messagesHtml = "";
        msgs.forEach(m => messagesHtml += `<div class="message">${m.message} (${m.timestamp})</div>`);
        html = html.replace("<!--USER_MESSAGES-->", messagesHtml);
        res.send(html);
      });
    });
  });
});

// Send message to user by link
app.post("/message/:username", (req,res)=>{
  const username = req.params.username;
  const { message } = req.body;
  db.get("SELECT * FROM users WHERE username=?", [username], (err,user)=>{
    if(!user) return res.send("User not found");
    db.run("INSERT INTO messages (user_id,message) VALUES (?,?)",[user.id,message], ()=>{
      res.send(`<p>Message sent!</p><p><a href="/message/${username}">Back</a></p>`);
    });
  });
});

// Message page for sending anonymously
app.get("/message/:username",(req,res)=>{
  const username = req.params.username;
  db.get("SELECT * FROM users WHERE username=?", [username], (err,user)=>{
    if(!user) return res.send("User not found");
    res.send(`
      <h2>Send anonymous message to ${username}</h2>
      <form method="POST" action="/message/${username}">
        <textarea name="message" placeholder="Your message..." required></textarea><br>
        <button type="submit">Send</button>
      </form>
    `);
  });
});

// Start server
app.listen(process.env.PORT || 3000, ()=>console.log("App running..."));