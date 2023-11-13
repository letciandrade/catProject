const User = require("../models/User");

const bcrypt = require("bcryptjs");

module.exports = class AuthController {
  static async registerPost(request, response) {
    const { name, email, password, repeatPassword } = request.body;

    //verificar as senhas
    if (password != repeatPassword) {
      request.flash("message", "As senha não conferem, tente novamente");
      response.render("home");
      return;
    }

    //Verificar se ja existe usuário
    const checkIfUserExist = await User.findOne({ where: { email: email } });
    if (checkIfUserExist) {
      request.flash("message", "O e-mail já está em uso");
      response.render("home");
      return;
    }

    //Segurança
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    const user = {
      name,
      email,
      password: hashedPassword,
    };

    try {
      const createUser = await User.create(user);
      request.session.userId = createUser.id;

      request.flash("message", "Cadastro Realizado com sucesso");
      request.session.save(() => {
        response.redirect("/");
      });
      return
    } catch (error) {
        console.log(error)
    }
  }

  static async loginPost(request, response) {
    const {email, password} = request.body

    const user = await User.findOne({where: {email:email}});
    if(!user){
        request.flash('message', "Usuário não encontrado")
        response.render('home')
        return
    }

    console.log('Chegou')

  }
};
