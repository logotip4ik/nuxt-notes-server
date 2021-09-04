const port = process.argv[2] || 8765
const express = require('express')
const helmet = require('helmet')
const expressSession = require('express-session')
const Gun = require('gun')
require('gun/sea')
require('gun/axe')

const app = express()

app.use(Gun.serve)

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

const server = app.listen(port)
// (latter) add Amazon S3 support
Gun({ file: 'data', web: server })

// global.Gun = Gun /// make global to `node --inspect` - debug only
// global.gun = gun /// make global to `node --inspect` - debug only

console.log('Server started on port ' + port + ' with /gun')
