const http = require('http')

const Gun = require('gun')
const express = require('express')
const helmet = require('helmet')
const expressSession = require('express-session')
const app = express()

// your express configuration here

const httpServer = http.createServer(app)

// For http
httpServer.listen(8080)

app.disable('x-powered-by')
app.use(helmet())
app.set('trust proxy', 1)
app.use(
  expressSession({
    resave: true,
    saveUninitialized: true,
    secret: 'just-some-secret',
    name: 'note-gun-server',
  })
)

app.get('/', (req, res) => {
  res.json({ msg: 'GO HOME.' })
})

Gun({ web: httpServer })
