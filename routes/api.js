const express = require('express');
const router = express.Router();

const fs = require('fs');
const jwa = require('jwa');
const sha1File = require('sha1-file');
const path = require('path');

//require multer for the file uploads
const multer = require('multer');
// // set the directory for the uploads to the uploaded to
var DIR = './uploads/';

//multer configs
let storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, DIR);
    },
    filename: (req, file, cb) => {
      cb(null, file.originalname);
    }
});


//define the type of upload multer would be doing and pass in its destination, in our case, its a single file with the name photo
var upload = multer({ storage: storage });


router.post('/sign', upload.single('file'),(req,res)=>{
  if (!req.file) {
      console.log("No file received");
      return res.send({
        success: false
      });

    } else {
      console.log('file received');


      //sign the file
      const privateKey = fs.readFileSync(__dirname + './../ecdsa-p521-private.pem');
      const ecdsa = jwa('RS512');
      console.log(req);

      //get SHA1
      sha1File(req.file.path, function (error, sum) {
          if (error) {
            console.log(error)
          }


          const input = sum;
          const signature = ecdsa.sign(input, privateKey);


          //delete file
          fs.unlink(req.file.path, (err) => {
            if (err) throw err;
            console.log(req.file.filename+' was deleted');
          });


          //return result to frontEnd
          return res.send({
            success: true,
            signature : signature
          });
        });
      }
});

router.post('/verify', upload.single('file'),(req,res)=>{
  if (!req.file) {
      console.log("No file received");
      return res.send({
        success: false
      });

    } else {
      console.log('file received');
      console.log(req.body.signature);
      //sign the file
      const publicKey = fs.readFileSync(__dirname + './../ecdsa-p521-public.pem');
      const ecdsa = jwa('RS512');

      //get SHA1
      sha1File(req.file.path, function (error, sum) {
          if (error) {
            console.log(error);
            return res.send(error);
          }


          const input = sum;
          const signature = req.body.signature;
          const verification = ecdsa.verify(input, signature, publicKey);

          //delete file
          fs.unlink(req.file.path, (err) => {
            if (err) throw err;
            console.log(req.file.filename+' was deleted');
          });

          //console.log(ecdsa.verify(input, signature, publicKey));

          //return result to frontEnd
          return res.send({
            success: true,
            verification : verification
          });
        });
      }
});






module.exports = router;
