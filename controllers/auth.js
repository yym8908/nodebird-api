const bcrypt = require('bcrypt');
const passport = require('passport');
const User = require('../models/user');

//회원가입 컨트롤러
exports.join = async (req, res, next) => {
    const {email, nick, password} = req.body;
    try{
        const exUser = await User.findOne({ where: {email}});
        if(exUser){
            return res.redirect('/join?error=exist');
        }
        const hash = await bcrypt.hash(password, 12);
        await User.create({
            email,
            nick,
            password: hash,
        });
        return res.redirect('/');
    }catch(error){
        console.log(error);
        return next(error);
    }
}

//로그인 컨트롤러
exports.login = (req, res, next) => {
    passport.authenticate('local', (authError, user, info) => {
        if(authError){
            console.error(authError);
            return next(authError);
        }
        if(!user){
            return res.redirect(`/?loginError=${info.message}`);
        }
        return req.login(user, (loginError) => {
            if(loginError){
                console.error(loginError);
                return next(loginError);
            }
            return res.redirect('/');
        });
    })(req, res, next);
}

//로그아웃 컨트롤러
exports.logout = (req, res) => {
    req.logout(()=>{
        res.redirect('/');
    });
};