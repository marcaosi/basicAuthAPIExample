
const express = require('express');
const basicAuth = require('express-basic-auth');

const app = express();

function getRole(user) {
    // Nesse ponto, pode-se abrir uma conexão com banco de dados ou outro serviço
    // e buscar a role do usuário a partir do username.
    if (user === 'admin') {
        return 'admin';
    } else {
        return 'commonUser';
    }
}

function authorize(...allowed) {
    const isAllowed = role => allowed.indexOf(role) > -1;

    return (req, res, next) => {
        if(req.auth.user) {
            const role = getRole(req.auth.user);
            if(isAllowed(role)) {
                next();
            } else {
                res.status(403).send("Operação não permitida");
            }
        } else {
            res.status(403).send("Usuário ausente");
        }
    }
}

app.use(['/findAll', '/findWhatever'], authorize('admin', 'commonUser'))
app.use('/findSomething', authorize('admin'))

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
