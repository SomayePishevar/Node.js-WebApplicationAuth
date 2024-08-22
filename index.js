import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;
const saltingRound = 10;
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
  const username = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("username already exists. Try logging in.");
    } else {
      bcrypt.hash(password, saltingRound, async (err, hash)=>{
        if(err){
          console.error("error hashing password: ", err);
        }else{
          const result = await db.query(
            "INSERT INTO users (username, password) VALUES ($1, $2)",
            [username, hash]
          );
          console.log(result);
          res.render("secrets.ejs");
        }
      }) 
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const loginPassword = req.body.password;

  try {
    const result = await db.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      console.log(user);
      const storedHashedPassword = user.password;
      bcrypt.compare(loginPassword, storedHashedPassword, (err, result)=>{
        if(err){
          console.error("Error comparing passwords: ", err);
        }else{
          if(result){
            res.render("secrets.ejs");
          }else{
            res.send("Incorrect Password");
          }
        }
      });
    } else {
      res.send("User not found");
    }
  } catch (err) {
    console.log(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
