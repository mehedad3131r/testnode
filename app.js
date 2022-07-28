const express = require('express')
var app = express();
app.use(express.json())
const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
// const UserModel =require
// import UserModel from './models/user.mjs';
// import PaymentModel from './models/payment.mjs';
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const JWTstrategy = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;


const portofserver = 8082;
// import mongoose from 'mongoose';
const mongoose = require('mongoose');
const { Schema } = mongoose;
const paymentSchema = Schema({
  author: { type: Schema.Types.ObjectId, ref: 'User' },
  title: String,
  amount: Number,
  coin: String,
  status: String
});
const userSchema = Schema({
  _id: Schema.Types.ObjectId,
  email: String,
  name: String,
  uid: Number,
  balance: Number,
  firstname: String,
  lastname: String,
  password: String,
  role: String,
  username: { type: String, unique: true },
  payments: [paymentSchema]
});
userSchema.pre(
  'save',
  async function (next) {
    const user = this;
    const hash = await bcrypt.hash(this.password, 10);

    this.password = hash;
    next();
  }
);

userSchema.methods.isValidPassword = async function (password) {
  const user = this;
  const compare = await bcrypt.compare(password, user.password);

  return compare;
}


const Payment = mongoose.model('Payment', paymentSchema);
const User = mongoose.model('User', userSchema);






main().catch(err => console.log(err));



async function main() {
  await mongoose.connect('mongodb://localhost:27017/satest');
  console.log('db connected')
}

async function seeder() {
  await User.find().remove().exec();
  await Payment.find().remove().exec();
  let userseed = await User.findOne({ username: 'mehrdadr133' }).exec();
  console.log(userseed)
  if(userseed){
    console.log('we find correct user')
  }else{
    const author = new User({
      _id: new mongoose.Types.ObjectId(),
      name: 'Ian Flddeming',
      balance: 50,
      uid: 1,
      firstname: 'mehdrdad',
      lastname: 'ddddd',
      password: 'Strindg',
      role: 'admin',
      email: 'String@sd.cdd',
      username: 'mehrdadr133'
    });
  
    const story1 = new Payment({
      title: 'mehrdad',
      author: author._id,    // assign the _id from the person
      amount: 20,
      coin: 'BTC',
      status: 'started'
    });
    author.payments.push(story1);
    author.save();
    console.log('user created')
  }

}

seeder();


/*
this is nodejs scrapper by selenium and puppeteer
projectby:mehrdad3131r@gmail.com
mobile:09394977332

*/


passport.use(
  new JWTstrategy(
    {
      secretOrKey: 'TOP_SECRET',
      jwtFromRequest: ExtractJWT.fromUrlQueryParameter('secret_token')
    },
    async (token, done) => {
      try {
        return done(null, token.user);
      } catch (error) {
        done(error);
      }
    }
  )
);

passport.use(
  'signup',
  new localStrategy(
    {
      usernameField: 'email',
      passwordField: 'password'
    },
    async (email, password, done) => {
      try {
        const user = new User({
          _id: new mongoose.Types.ObjectId(),
          email: email,
          uid: 1,
          name: email,
          balance: 50,
          firstname: email,
          lastname: email,
          password: password,
          username: email
        });
        // const user = await User.create({ email, password });

        return done(null, user);
      } catch (error) {
        done(error);
      }
    }
  )
);

passport.use(
  'login',
  new localStrategy(
    {
      usernameField: 'email',
      passwordField: 'password'
    },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email: email }).exec();
        console.log(user)
        if (!user) {
          return done(null, false, { message: 'User not found' });
        }

        const validate = await user.isValidPassword(password);

        if (!validate) {
          return done(null, false, { message: 'Wrong Password' });
        }

        return done(null, user, { message: 'Logged in Successfully' });
      } catch (error) {
        return done(error);
      }
    }
  )
);

app.get('/', async function (req, res) {
  res.send('server is running on port: ' + portofserver)
})

app.get('/allusers', async function (req, res) {
  let allUsers = await User.find();
  let json = { "result": 'success', "data": allUsers }
  res.send(json)
})

app.get('/alluserspayment', async function (req, res) {
  let user = await User.findOne({ uid: req.query.uid }).exec();
  if(!user){
    throw 'usernot found';
  }
  // var data
  if(user.role == 'admin'){
    let allpayments = await Payment.find({}, function (err, docs) {
      if (err){
          console.log(err);
      }
      else{
          console.log("First function call : ", docs);
      }
  });
    console.log(111111)
    console.log(allpayments)
    let admindata = { "result": 'success', "data": allpayments }
    res.send(admindata)
  }else{
    let allpaymentsforuser = await Payment.find({ author: user._id }).exec();
    let userdata = { "result": 'success', "data": allpaymentsforuser }
    console.log(2222222)
    console.log(allpaymentsforuser)
    res.send(userdata)
  }
  
})

// const router = express.Router();

// ...

app.post(
  '/login',
  async (req, res, next) => {
    passport.authenticate(
      'login',
      async (err, user, info) => {
        try {
          if (err || !user) {
            const error = new Error('An error occurred.');

            return next(error);
          }

          req.login(
            user,
            { session: false },
            async (error) => {
              if (error) return next(error);

              const body = { _id: user._id, email: user.email };
              const token = jwt.sign({ user: body }, 'TOP_SECRET');

              return res.json({ token });
            }
          );
        } catch (error) {
          return next(error);
        }
      }
    )(req, res, next);
  }
);

app.post(
  '/signup',
  passport.authenticate('signup', { session: false }),
  async (req, res, next) => {
    res.json({
      message: 'Signup successful',
      user: req.user
    });
  }
);


app.get('/payments', passport.authenticate('jwt', { session: false }), async function (req, res) {
  // await User.find().remove().exec();
  // await Payment.find().remove().exec();
  // const author = new User({
  //   _id: new mongoose.Types.ObjectId(),
  //   name: 'Ian Flddeming',
  //   balance: 50,
  //   firstname: 'mehdrdad',
  //   lastname: 'ddddd',
  //   password: 'Strindg',
  //   email: 'String@sd.cdd',
  //   username: 'mehrdadr133'
  // });

  // //   author.save();

  // const story1 = new Payment({
  //   title: 'mehrdad',
  //   author: author._id,    // assign the _id from the person
  //   amount: 20,
  //   coin: 'BTC',
  //   status: 'started'
  // });
  // author.payments.push(story1);

  // author.save();
  res.send('app runned');
})

app.get('/paymenttst', async function (req, res) {
  // const token = 
  const user = User.findOne({ username: 'mehrdadr133' })
  const body = { _id: user._id, email: user.email };
  const token = jwt.sign({ user: body }, 'TOP_SECRET');
  res.send(token);
})


app.get('/paymenttst', async function (req, res) {
  // const token = 
  const user = User.findOne({ username: 'mehrdadr133' })
  const body = { _id: user._id, email: user.email };
  const token = jwt.sign({ user: body }, 'TOP_SECRET');
  res.send(token);
})


app.get(
  '/profile',
  (req, res, next) => {
    res.json({
      message: 'You made it to the secure route',
      user: req.user,
      token: req.query.secret_token
    })
  }
);
var server = app.listen(portofserver, function () {
  var host = server.address().address
  var port = server.address().port
  console.log("Example app listening at http://%s:%s", host, port)
})