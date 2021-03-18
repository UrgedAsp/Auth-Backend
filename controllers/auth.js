const { response } = require('express')
const Usuario = require('../models/Usuario')
const bcrypt = require('bcryptjs')
const { generarJWT } = require('../helpers/jwt')


const crearUsuario = async(req, res = response) => {

    const { email, name, password } = req.body

    try {
        // Verificar el email
        let usuario = await Usuario.findOne({ email });

        if (usuario) {
            return res.status(400).json({
                ok: false,
                msg: 'El email ya esta en uso'
            })
        }

        // Crear usuario con el modelo
        usuario = new Usuario(req.body);

        // Hashear la contraseña
        const salt = bcrypt.genSaltSync();
        usuario.password = bcrypt.hashSync(password, salt);

        //  Generar el JWT
        const token = await generarJWT(usuario.id, name);

        // Crear usuario de BD
        await usuario.save();

        // Generar respuesta exitosa
        return res.status(201).json({
            ok: true,
            uid: usuario.id,
            name,
            email,
            token
        })

    } catch (error) {
        return res.status(500).json({
            ok: false,
            msg: 'Porfavor comunicarse con Camilo Reyes'
        })
    }

}

const loginUsuario = async(req, res = response) => {

    const { email, password } = req.body


    try {

        const dbUser = await Usuario.findOne({ email });

        if (!dbUser) {
            return res.status(400).json({
                ok: false,
                msg: 'El correo no existe'
            })
        }

        // Confirmar si el password hace match
        const validPasword = bcrypt.compareSync(password, dbUser.password)

        if (!validPasword) {
            return res.status(400).json({
                ok: false,
                msg: 'El password no es valido'
            })
        }


        //  Generar el JWT
        const token = await generarJWT(dbUser.id, dbUser.name);

        // Respuesta del servicio
        return res.json({
            ok: true,
            uid: dbUser.id,
            name: dbUser.name,
            email,
            token
        })


    } catch (error) {
        console.log(error);
        return res.status(500).json({
            ok: false,
            msg: 'Hable con el Camilo Reyes'
        })

    }

}

const revalidarToken = async(req, res) => {

    const { uid } = req;

    //Leer la base de datos
    const dbUser = await Usuario.findById(uid);



    // Generar JWT
    const token = await generarJWT(uid, dbUser.name)

    return res.json({
        ok: true,
        uid,
        name: dbUser.name,
        email: dbUser.email,
        token
    })

}

module.exports = {
    crearUsuario,
    loginUsuario,
    revalidarToken
}