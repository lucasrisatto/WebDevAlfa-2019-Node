const {
    Usuario
} = require('../models/index')

const {
    generateToken, compare, authenticationMiddleware
} = require('../utils/token')

const {
    isCPF
} = require('../utils/customValidators')

const bcrypt = require('bcryptjs')
const saltRounds = 10

function cadastro(req, res, next) {
    const usuario = req.body;

    if (!isCPF(usuario.cpf)) {
        res.status(422).send('CPF invalido');
    }

    Usuario.create({
        nome: usuario.nome,
        email: usuario.email,
        nascimento: usuario.nascimento,
        cpf: usuario.cpf,
        senha: bcrypt.hashSync(usuario.senha, saltRounds) // estudar sobre hash de senha com bcrypt
    })
        .then(function (usuarioCriado) {
            // usuário inserido com sucesso
            const usuarioJson = usuarioCriado.toJSON()
            delete usuarioJson.senha;
            res.status(201).json(usuarioJson)
        })
        .catch(function (error) {
            // falha ao inserir o usuário
            if (Array.isArray(error.errors)) {
                const sequelizeError = error.errors[0]
                if (sequelizeError.type === 'unique violation' &&
                    sequelizeError.path === 'email') {
                    res.status(422).send('O e-mail informado já existe no banco de dados.');
                    return;
                }
            }
            res.status(422).send();
        })
}

function buscaPorId(req, res, next) {
    const usuarioId = req.params.usuarioId

    Usuario.findByPk(usuarioId)
        .then(function (usuario) {
            if (usuario) {
                const usuarioJson = usuario.toJSON()
                delete usuarioJson.senha
                res.status(200).json(usuarioJson)
            } else {
                res.status(404).send()
            }
        })
        .catch(function (error) {
            console.log(error)
            res.status(422).send()
        })
}

function edicao(req, res, next) {
    const usuarioId = req.params.usuarioId
    const body = req.body

    Usuario.findByPk(usuarioId)
        .then(function (usuario) {
            if (usuario) {
                return usuario.update({
                    nome: body.nome,
                    email: body.email,
                    nascimento: body.nascimento,
                    cpf: body.cpf,
                    senha: bcrypt.hashSync(body.senha, saltRounds)
                })
                    .then(function (usuarioAtualizado) {
                        const usuarioJson = usuarioAtualizado.toJSON()
                        delete usuarioJson.senha
                        res.status(200).json(usuarioJson)
                    })
            } else {
                res.status(404).send()
            }
        })
        .catch(function (error) {
            console.log(error)
            res.status(422).send()
        })
}

function listagem(req, res, next) {
    Usuario.findAll({
        attributes: ['id', 'nome', 'nascimento', 'email', 'senha', 'cpf'], 
    })
    .then(function(usuarios) {
        res.status(200).json(usuarios)
    })
    .catch(function(error) {
        console.log(error)
        res.status(422).send()
    })
}

function login(req, res, next) {
    const email = req.body.email;
    const senha = req.body.senha;
    Usuario.findOne({
        attributes: ['id', 'nome', 'email', 'senha'],
        where: { email: email }
    }).then(function (usuario) {
        if (usuario) {
            compare(senha, usuario.senha)
                .then((passwordMatch) => {
                    if (!passwordMatch) {
                        return res.status(401).send();
                    }

                    const usuarioJson = usuario.toJSON();
                    const token = generateToken(usuarioJson)

                    res.json({ token })
                })
        } else {
            res.status(401).send('E-mail ou senha incorretos')
        }
    })
}

module.exports = {
    cadastro,
    buscaPorId,
    edicao,
    login,
    listagem
};