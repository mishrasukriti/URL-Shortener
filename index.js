const mongodb = require("mongodb")
const cors = require("cors")
const express = require("express");
const dotenv = require("dotenv")
const bcrypt = require("bcrypt")
const nodemailer = require("nodemailer")
const btoa = require('btoa')
const atob = require('atob')

const mongoClient = mongodb.MongoClient
const objectId = mongodb.ObjectID
const ISODate = mongodb.ISODate
const app = express();
let port = process.env.PORT || 3000;
app.listen(port, ()=>console.log(`The app is running on port: ${port}`));
app.use(express.json());
app.use(cors())
dotenv.config()

const url = process.env.DB_URL || 'mongodb://127.0.0.1:27017';
var transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
         user: process.env.email,
         pass: process.env.password
     }
 });

 const mailOptions = {
  from: process.env.email, // sender address
  to: '', // list of receivers
  subject: 'Password reset', // Subject line
  html: ''// plain text body
};


app.put("/reset-password", async(req, res)=>{
  try{
    console.log("Inside rest-password api ");
    let client = await mongodb.connect(url);
    let db = client.db("url_db");
    let data = await db.collection("users").findOne({ email: req.body.email });
    let salt = await bcrypt.genSalt(8);
    if (data) {
      console.log("Inside data part of rest-password api ");
      let randomStringData = {randomString : salt}
      await db.collection("users").findOneAndUpdate({email: req.body.email}, {$set :randomStringData})
      mailOptions.to = req.body.email;
      let resetURL = process.env.resetUrl;
      console.log("resetUrl is: "+ resetURL);
      resetURL = resetURL+"?id="+data._id+"&rs="+salt;
      
      console.log("final reswturl is: "+ resetURL);

      let sampleMail = '<p>Hi,</p>'
      + '<p>Please click on the link below to reset your Password</p>'
      + '<a target="_blank" href='+ resetURL +'>' +  resetURL + '</a>'
      + '<p>Regards,</p>';

      let resultMail = sampleMail;
      console.log("resultMail is: "+ resultMail);
      mailOptions.html = resultMail;
      await transporter.sendMail(mailOptions)
      res.status(200).json({
        message: "Verification mail sent"
      });
      } else {
        res.status(400).json({
          message: "User is not registered"
        });
      }
    client.close();
  }
  catch(error){
    res.status(500).json({
        message: "Internal Server Error"
    })
}

})

app.put("/change-password/:id", async(req, res)=>{
    try{
        let client = await mongoClient.connect(url)
        let db = client.db("url_db")
        let salt = await bcrypt.genSalt(10);
        let hash = await bcrypt.hash(req.body.password, salt);
        req.body.password = hash;
        let result = await db.collection("users").findOneAndUpdate({_id: objectId(req.params.id)}, {$set :req.body})
        res.status(200).json({
            message : "Password Changed Successfully"
        })
        client.close()
    }
    catch(error){
        res.status(500).json({
            message: "Error while changing the password"
        })
    }
})


app.post("/register", async (req, res) => {
    try {
      let client = await mongodb.connect(url);
      let db = client.db("url_db");
      
      let data = await db.collection("users").findOne({ email: req.body.email });
      if (data) {
        console.log("Inside data part true of register api");
        res.status(400).json({
          message: "User already exists",
        });
      } else {
        // console.log("Inside else of data part true of register api");
        let randomString = await bcrypt.genSalt(8);
        let salt = await bcrypt.genSalt(10);
        let hash = await bcrypt.hash(req.body.password, salt);
        req.body.password = hash;
        let reqData = req.body;
        // console.log("reqDAta is: "+ reqData);
        
        reqData["activateString"] = randomString;
        await db.collection("users").insertOne(reqData);
        data = await db.collection("users").findOne({ email: req.body.email });
        mailOptions.to = req.body.email
        mailOptions.subject = "Activation mail"
        let activateURL = process.env.activateURL;
        // console.log("activateURL is: "+ activateURL);
        activateURL = activateURL+"?id="+data._id+"&ac="+randomString
        
        let activateMail = '<p>Hi,</p>'
                 + '<p>Please click on the link below to activate your account</p>'
                 + '<a target="_blank" href='+ activateURL +' >' +  activateURL + '</a>'
                 + '<p>Regards,</p>'


        
        // console.log("result mail is: "+ activateMail);
        
        mailOptions.html = activateMail
        await transporter.sendMail(mailOptions);
        res.status(200).json({
          message: "Activation mail sent",
        });
      }
      client.close();
    } catch (error) {
      res.status(500).json({
        message: "Internal Server Error"
      });
    }
  });
  
  app.post("/login", async (req, res) => {
    try {
      let client = await mongodb.connect(url);
      let db = client.db("url_db");
      let data = await db.collection("users").findOne({ email: req.body.email });
      if (data) {
        let isValid = await bcrypt.compare(req.body.password, data.password);
        if (isValid) {
          if(data.isActivated === "true"){
            res.status(200).json({ message: "Login success" });
          }
          else{
            res.status(401).json({ message: "Account not activated" });
          }
          
        } else {
          res.status(401).json({ message: "Incorrect password" });
        }
      } else {
        res.status(400).json({
          message: "User is not registered",
        });
      }
      client.close();
    } catch (error) {
      res.status(500).json({
          message: "Internal Server Error"
      });
    }
  });


  app.post("/passwordResetLink-verification", async (req, res) => {
    try {
      let client = await mongodb.connect(url);
      let db = client.db("url_db");
      let data = await db.collection("users").findOne({ _id: objectId(req.body.objectId) });
      if (data.randomString === req.body.randomString) {
        res.status(200).json({ message: "Verification successfull" });
      } else {
        res.status(401).json({
          message: "You are not authorized",
        });
      }
      client.close();
    } catch (error) {
      res.status(500).json({
          message: "Internal Server Error"
      });
    }
  });

  app.post("/activate_account", async (req, res) => {
    try {
      let client = await mongodb.connect(url);
      let db = client.db("url_db");
      let data = await db.collection("users").findOne({ _id: objectId(req.body.id) });
      if (data.activateString === req.body.randomString) {
        let activation = {isActivated : "true"}
        await db.collection("users").findOneAndUpdate({_id: objectId(req.body.id)}, {$set :activation})
        res.status(200).json({ message: "Verification success" });
      } else {
        res.status(401).json({
          message: "You are not authorized",
        });
      }
      client.close();
    } catch (error) {
      res.status(500).json({
          message: "Internal Server Error"
      });
    }
  });



  app.post("/shortenURL", async (req, res) => {
    try {
      var longURL = req.body.longURL
      let client = await mongodb.connect(url);
      let db = client.db("url_db");
      let data = await db.collection("url_collection").findOne({ long_url : longURL });
      if(data){
        let shortURL = "http://127.0.0.1:5500/frontend/index.html" + "?id=" + btoa(data._id)
        console.log("shortened URL will be: " + shortURL);
        res.status(200).json({
          message : "URL is shortened",
          shortenedURL :  shortURL
        })
      }
      else{
        await db.collection("url_collection").insertOne({long_url: longURL});
        data = await db.collection("url_collection").findOne({ long_url : longURL });
        let shortURL = process.env.baseURL + "?id=" + btoa(data._id)
        let currentDate = new Date()
        let count_data = {ping_time: new Date(currentDate.toISOString())}
        await db.collection("count_ping").insertOne(count_data);
        res.status(200).json({
          message : "URL is shortened",
          shortenedURL :  shortURL
        })
      }
      client.close();
    } catch (error) {
      res.status(500).json({
          message: "Internal Server Error"
      });
    }
  });



app.get("/hash/:hash", async (req, res) => {
  try{
    var baseid = req.params.hash;
    var id = atob(baseid);
    let client = await mongodb.connect(url);
    let db = client.db("url_db");
    let data = await db.collection("url_collection").findOne({ _id : objectId(id) });    
    if(data) {
        res.status(200).json({
          message : "Success",
          longURL : data.long_url
        })
    } else {
      res.status(403).json({
        message : "Not Authorized",
      })
    }
    client.close()
  }
  catch (error) {
    res.status(500).json({
        message: "Internal Server Error"
    });
  }
});

app.get("/get_count", async(req, res)=>{
  try{
    let client = await mongodb.connect(url);
    let db = client.db("url_db");
    
    let currentDate = new Date()
    let oneDay = new Date()
    oneDay.setDate(oneDay.getDate() - 1);
    let thirtyDay = new Date()
    thirtyDay.setDate(thirtyDay.getDate() - 30);
    let onedayList = await db.collection("count_ping").
              find({ping_time:{
                $gte: new Date(oneDay.toISOString()),
                $lte: new Date(currentDate.toISOString())
              }}).toArray();  

    let thirtydayList = await db.collection("count_ping").
              find({ping_time:{
                $gte: new Date(thirtyDay.toISOString()),
                $lte: new Date(currentDate.toISOString())
              }}).toArray();  
    let oneDayCount = onedayList.length
    let thirtyDayCount = thirtydayList.length
    res.status(200).json({
      message : "Success",
      oneDayCount : oneDayCount,
      thirtyDayCount : thirtyDayCount
    })
    
    client.close()

  }
  catch (error) {
    res.status(500).json({
        message: "Internal Server Error"
    });
  }
})
