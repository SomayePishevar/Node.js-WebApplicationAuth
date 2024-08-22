import express from "express";
import bodyParser from "body-parser";
import pg from "pg";

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
const db = new pg.Client({
  user: 'myuser',
  host: 'localhost',
  database: 'authentication',
  password: 'mypassword',
  port: 5432,
})
db.connect();
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;
    const checkresult = (await db.query("select * from users u where u.username = $1 ", [username])).rows;
    if(checkresult){
      res.send("The email already exists. Try logging in.");
    }else{
      await db.query("insert into users (username, password) values ($1, $2)", [username, password]);
      console.log(username);
      console.log(password);
      res.redirect("secrets.ejs");
    }
  } catch (error) {
    console.error(error.message);
    res.status(500).send("an error occured while adding user");
  }
});

app.post("/login", async (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;
    console.log(password);
    const user = (await db.query("select * from users u where u.username = $1 ", [username])).rows;
    console.log(user);
    console.log(!user.length>0);
    if(!user.length>0){
      res.send("User does not exist.")
    }else if(user[0].password === password){
      res.redirect("secrets.ejs");
    }else{
      res.send("Paasword is not correct.")
    }
    
  } catch (error) {
    console.error(error.message);
    res.status(500).send("an error occured while logging in");
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
