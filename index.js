import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth2";

const app = express();
const port = 3000;
const saltingRound = 10;
env.config();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge : 1000 * 60 * 60 * 24,
  },
})
);

app.use(passport.initialize());
app.use(passport.session());
const db = new pg.Client({
  user: process.env.DATABASE_USER,
  host: process.env.DATABASE_HOST,
  database: process.env.DATABASE_NAME,
  password: process.env.DATABASE_PASSWORD,
  port: process.env.DATABASE_PORT,
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

app.get("/secrets", async (req, res)=>{
  console.log(req.user);
  if(req.isAuthenticated()){
    const secret = await (await db.query("SELECT secrets FROM users where username = $1", [req.user.username])).rows
    if(secret){
      res.render("secrets.ejs", {secret : secret});
    }else{
      res.render("secrets.ejs", {secret : "You should submit a secret!"});
    }
    
  }else{
    res.redirect("/login");
  }
})

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req,res) => {
  req.logout((err)=> {
    if(err) console.error(err);
    res.redirect("/");
  })
})

app.get("/submit", (req,res)=>{
  if(req.isAuthenticated()){
    res.render("submit.ejs")
  }else{
    res.redirect("/login");
  }
  
})
app.post("/submit", async(req, res)=>{
  const newSecret =  req.body.secret;
  console.log(req.user.username);
  await db.query("update users set secrets = $1 where username = $2", [newSecret, req.user.username]);
  res.redirect("/secrets");
})

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
            "INSERT INTO users (username, password) VALUES ($1, $2) returning *",
            [username, hash]
          );
          const user = result.rows[0];
          req.login(user, (err)=> {
            console.log(err); 
            res.redirect("/secrets")
          })
          console.log(result);
          res.render("secrets.ejs");
        }
      }) 
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", passport.authenticate("local",{
  successRedirect: "/secrets", 
  failureRedirect: "/login"
}));

passport.use(new Strategy(async function verify(username, password, cb){
  console.log(username);

  try {
    const result = await db.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      console.log(user);
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, valid)=>{
        if(err){
          console.error("Error comparing passwords: ", err);
          return cb(err);
        }else{
          if(valid){
            return cb(null, user);
          }else{
            return cb(null, false);
          }
        }
      });
    } else {
      return cb("User not found");
    }
  } catch (err) {
    console.log(err);
  }
})); 

passport.use("google", new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
  }, async (accessToken, refereshToken, profile, cb)=>{
  console.log(profile);
  try {
    const result = await db.query("SELECT * FROM users WHERE username = $1", [
      profile.email,
    ]);
    
    if (result.rows.length === 0) {
      const newUser = await db.query(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        [profile.email, "google"]
      );
      return cb(null, newUser.rows[0]);
    } else {
      return cb(null, result.rows[0]);
    }
  } catch (error) {
    return cb(err);
  }
}));



passport.serializeUser((user, cb)=>{
  cb(null, user);
});
passport.deserializeUser((user, cb)=>{
  cb(null, user);
})
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
