
const express      = require('express');
const jsonwebtoken = require('jsonwebtoken');
const bodyParser   = require('body-parser');
const bcrypt       = require('bcrypt');
const fs = require('fs')

const app = express();
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());

function authorize(...allowed) {
    const isAllowed = role => allowed.indexOf(role) > -1;

    return (req, res, next) => {
        const token = req.headers['token'];

        if(!token){
            res.status(401).json({ message: 'Denied Access' })
        }

        const publicKey = fs.readFileSync("./public.key", "utf8")

        jsonwebtoken.verify(token, publicKey, { algorithms: [ 'HS256' ] }, (err, decodedToken) => {
            if(err){
                res.status(401).json({ message: 'Invalid token' })
            }

            if(isAllowed(decodedToken.role)) {
                next();
            } else {
                res.status(403).send("Denied Access");
            }
        })
    }
}

app.use(['/findAll', '/findWhatever'], authorize('admin', 'commonUser'))
app.use('/findSomething', authorize('admin'))

var users = {};

app.post('/createUser', (req, res) => {

    const encryptedPass = bcrypt.hashSync(req.body.password, 1);

    users[req.body.username] = {
        pwd: encryptedPass,
        role: req.body.role
    };

    console.log(`encryptedPass: ${encryptedPass}`);

    res.json(`User ${req.body.username} created.`);
})

app.post('/login', (req, res) => {
    if(req.body.username && req.body.password){
        if(users[req.body.username]){
            const user = users[req.body.username];
            const pwdMatches = bcrypt.compareSync(req.body.password, user.pwd);

            const privateKey = fs.readFileSync("./private.key", "utf8")

            if(pwdMatches) {
                const token = jsonwebtoken.sign(
                    { disciplina: 'AAS', role: user.role },
                    privateKey,
                    { expiresIn: 300, algorithm: 'HS256' }
                );

                res.json({ auth: true, token })
            } else {
                res.status(401).json({ message: 'Incorret Password' });
            }
        } else {
            res.status(401).json({ message: 'Invalid User' });
        }
    } else {
        res.status(401).json({ message: 'Empty User' });
    }
})

app.get('/findSomething', (req, res) => {
    res.send('Autenticação funcionou! findSomething')
})

app.get('/findAll', (req, res) => {
    res.send('Autenticação funcionou! findAll')
})

app.get('/findWhatever', (req, res) => {
    res.send('Autenticação funcionou! findWhatever')
})

app.listen(3000, () => console.log('Servidor iniciado'));
