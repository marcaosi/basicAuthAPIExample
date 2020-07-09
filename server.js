
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

app.use(basicAuth({
    authorizer: (username, password) => {
        console.log(`username: ${username}, password: ${password}`);

        // Nesse ponto, pode-se abrir uma conexão com banco de dados ou outro serviço
        // e buscar as informações do usuário a partir do username.
        // Para o exemplo, teremos apenas dois usuários

        // Importante: Usar safeCompare para evitar timing attack
        const adminUserMatches = basicAuth.safeCompare(username, 'admin');
        const adminPwdMatches = basicAuth.safeCompare(password, 'admin');

        const userMatches = basicAuth.safeCompare(username, 'professor');
        const pwdMatches = basicAuth.safeCompare(password, '1234');

        return adminUserMatches && adminPwdMatches || userMatches && pwdMatches;
    }
}))

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
