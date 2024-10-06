import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import mysql from 'mysql';
import dotenv from 'dotenv'
import bcrypt from 'bcrypt'
import ejs from 'ejs'
import session from 'express-session'
import passport, { Passport } from 'passport'
import { Strategy as LocalStrategy } from 'passport-local';
import GoogleStartegy from 'passport-google-oauth2';
import cors from 'cors'

const app = express();
const port = 3000;
var saltRounding = 10;

dotenv.config();
// Create __dirname equivalent for ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'src/public')));

app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine','ejs');

app.use(cors({
    origin : process.env.CORS_URL,
    credentials: true,
}
))
app.use(session(
    {
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: {
            maxAge: 1000 * 60 *120,
            secure: false,
        }
    }
));
 app.use(passport.initialize());
 app.use(passport.session());


const db = mysql.createConnection({
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD
}

)

db.connect(err => {
    if(err){
        console.log(`Database connection rejected due to this + ${err}`);
        return;
    }
    console.log("Database connected");
    
})


// Serve the index.html file
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, 'src/public', 'index.html'));
});

app.get("/Home",(req,res) => {
    if(req.isAuthenticated() ){
        
        // console.log('session:', req.session);
        // console.log('User:', req.user);
        return res.render('error.ejs', {  heading: "Success" ,message: `You have been logged in  ${req.user.firstname}`, redirectUrl: '/Success' });
    }
    else{
       return res.redirect("/");
    }
})

app.get("/UsernameDetails", (req, res) => {
    if (req.isAuthenticated()) {
      const query = "SELECT email, lastname, ContactInfo FROM user_record WHERE firstname = ?";
      
      db.query(query, [req.user.firstname], (err, results) => {
        if (err) {
          console.log(err.code);
          return res.status(500).send("Internal Server Error");
        }
  
        if (results.length > 0) {
          // Successfully retrieved data from the database
        //   console.log(results[0]);
  
          // Send the results as the response
          return res.json({
            firstName: req.user.firstname,
            email: results[0].email,
            lastname: results[0].lastname,
            ContactInfo: results[0].ContactInfo,
              // Use the first result (assuming firstname is unique)
          });
        } else {
          // No results found
          console.log("No matching records found");
          return res.status(404).send("No matching records found");
        }
      });
    } else {
      return res.status(401).send("Unauthorized access. Please log in.");
    }
  });
  

app.get("/Success",(req,res) =>{
    // return res.render('success.ejs');
     console.log(req.user.firstname);
    //  return res.json({
    //     firstName: req.user.firstname,
    //    })
    return res.redirect('http://localhost:5173/');
    
   
})

app.get("/auth/google",passport.authenticate('google',{
    scope: ["profile","email"]
}))

app.get("/auth/google/secrets", passport.authenticate("google" , {
    successRedirect: "/Success",
    failureRedirect: "/"
}))




app.post("/Login", (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            // If user is false, it means authentication failed
            return res.render('error', { heading: 'Login Failed', message: info.message, redirectUrl: '/' });
        }
        req.logIn(user, (err) => {
            if (err) {
                return next(err);
            }
            return res.redirect('/Home');
        });
    })(req, res, next);
});


    




app.post("/Signup",(req,res)=> {
    const {signName, signLastName, logemail,SignPassword} = req.body;
    const query = "INSERT INTO user_record (email, password, lastname, firstname) VALUES (?, ?, ?, ?)";
    // console.log(SignPassword)
    bcrypt.hash(SignPassword,saltRounding,(err,hashValue) => {
        if(err){
            console.log(err);
        }
        else {
            // console.log(hashValue);
            db.query(query,[logemail,hashValue,signLastName,signName],(err, result) => {
                if(err){
                    if(err.code === "ER_DUP_ENTRY"){
                        return res.render('error', { heading: 'Failed', message: "Current email is already registered. Try Logging in", redirectUrl: '/' });
                    }
                    res.status(500).send("We faced an internal issue");
                    console.log(err);
                    return;
                }
                // console.log(result);
                return res.render('error', { heading: 'Success', message: "Your details has been saved. Try logging", redirectUrl: '/' });
            })
        }
    })
})
// Uisng passport.use we creating new object for LocalStratergy. The function takes three arguments and among one is 
// the call back function. This username and password will be taken automatically from the login form unitl
// the name is username and password in the form
passport.use('local',new LocalStrategy(async function verify(username, password, cb) {
    try {
        const query = "SELECT firstname, password FROM user_record WHERE email = ?";
        await db.query(query, [username], (err, results) => {
            if (err) {
                console.log(err);
                return cb(err);
            }

            if (results.length === 0) {
                // No user found with this email
                return cb(null, false, { message: "Email not registered. Please sign up first." });
            }

            const user = results[0];
            const hashedPassword = user.password;

            bcrypt.compare(password, hashedPassword, (err, isMatch) => {
                if (err) {
                    console.log(err);
                    return cb(err);
                }

                if (isMatch) {
                    // Password matches
                    return cb(null, user);
                } else {
                    // Password does not match
                    return cb(null, false, { message: "Incorrect password. Please try again." });
                }
            });
        });
    } catch (error) {
        return cb(error);
    }
}));

passport.serializeUser((user,cb)=> {
    cb(null,user);
})

passport.deserializeUser((user,cb) => {
    cb(null,user);
})


passport.use('google', 
    new GoogleStartegy ({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL : "http://localhost:3000/auth/google/secrets",
        userProfileURL: "http://www.googleapis.com/oauth2/v3/userinfo"
    },
    async (accessToken, refreshToken, profile, cb) => {

        console.log(profile);
        try {
            const query = "SELECT * FROM user_record WHERE email = ?";
            await db.query(query, [profile.email], (err, results) => {
                if (err) {
                    console.log(err);
                    return cb(err);
                }

                if (results.length > 0) {
                    // User exists, log them in
                    return cb(null, results[0]);
                } else {
                    // User doesn't exist, create a new one
                    const insertQuery = "INSERT INTO user_record (email, password, firstname, lastname) VALUES (?, ?, ?, ?)";
                    const password = 'google'; // Store 'google' as a placeholder password for Google users
                    const firstName = profile.given_name || '';
                    const lastName = profile.family_name || '';

                    db.query(insertQuery, [profile.email, password, firstName, lastName], (err, result) => {
                        if (err) {
                            console.log(err);
                            return cb(err);
                        }
                        // Fetch the new user
                        db.query(query, [profile.email], (err, newUserResults) => {
                            if (err) {
                                console.log(err);
                                return cb(err);
                            }
                            return cb(null, newUserResults[0]);
                        });
                    });
                }
            });
        } catch (error) {
            return cb(error);
        }
    }
));

app.listen(port, () => {
    console.log(`Server started running on port ${port}`);
});
