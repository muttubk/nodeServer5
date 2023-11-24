const express = require('express')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const dotenv = require('dotenv')
dotenv.config()
const cors = require('cors')

const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

app.use(cors())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

const User = mongoose.model('User', {
    fullname: String,
    email: String,
    password: String,
    isPremium: {
        type: Boolean,
        default: false
    }
})

// sample middleware for login authentication
const isLoggedIn = (req, res, next) => {
    try {
        const { jwtoken } = req.headers
        const user = jwt.verify(jwtoken, process.env.JWT_SECRET)
        req.user = user
        next()
    } catch (error) {
        res.json({
            status: 'FAILED',
            message: "You're not logged in"
        })
    }
}

// middleware for premium user authorization
const isPremium = (req, res, next) => {
    if (req.user.isPremium) {
        next()
    } else {
        res.json({
            status: 'FAILED',
            message: "You're not a Premium user! Buy a premium plan"
        })
    }
}

app.get('/', (req, res) => {
    res.json({
        status: 'SUCCESS',
        message: 'Welcome'
    })
})

app.get('/dashboard', isLoggedIn, (req, res) => {
    res.json({
        status: 'SUCCESS',
        message: 'Welcome to dashboard!'
    })
})

app.get('/premium', isLoggedIn, isPremium, (req, res) => {
    res.json({
        status: 'SUCCESS',
        message: 'Welcome to Preium page!'
    })
})

app.post('/signup', async (req, res) => {
    try {
        const { fullname, email, password, isPremium } = req.body
        const encryptedPassword = await bcrypt.hash(password, 10)
        await User.create({ fullname, email, password: encryptedPassword, isPremium })
        res.json({
            status: 'SUCCESS',
            message: "You've signed up successfully"
        })
    } catch (error) {
        res.json({
            status: 'FAILED',
            message: 'Something went wrong'
        })
    }
})

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body
        const user = await User.findOne({ email })
        if (user) {
            let passwordMatched = await bcrypt.compare(password, user.password)
            if (passwordMatched) {
                const jwToken = jwt.sign(user.toJSON(), process.env.JWT_SECRET, { expiresIn: 60 })
                res.json({
                    status: 'SUCCESS',
                    message: "You've logged in successfully",
                    jwToken
                })
            }
            else {
                res.json({
                    status: 'FAILED',
                    message: "Invalid credentials"
                })
            }
        }
        else {
            res.json({
                status: 'FAILED',
                message: 'User does not exist'
            })
        }
    } catch (error) {
        res.json({
            status: 'FAILED',
            message: 'Invalid credentials'
        })
    }
})

app.patch('/subscribePremium', async (req, res) => {
    try {
        const { email, isPremium } = req.body
        const id = await User.findOne({ email })
        await User.findByIdAndUpdate(id, { isPremium })
        res.json({
            status: 'SUCCESS',
            message: "You've subscribed successfully"
        })
    } catch (error) {
        res.json({
            status: 'FAILED',
            message: 'Something went wrong'
        })
    }
})

app.listen(process.env.PORT, () => {
    mongoose.connect(process.env.MONGODB_URL)
        .then(() => console.log(`Server running on http://localhost:${process.env.PORT}`))
        .catch((error) => console.log(error))
})