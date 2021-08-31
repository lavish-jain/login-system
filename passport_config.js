const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

const initialize = (passport, get_user_by_email, get_user_by_id) => {
  const authenticate_user = async (email, password, done) => {
    const user = get_user_by_email(email);
    if (!user)
      return done(null, false, { message: "No user with given email" });
    try {
      if (await bcrypt.compare(password, user.password)) {
        return done(null, user);
      } else {
        return done(null, false, { message: "Incorrect password" });
      }
    } catch (err) {
      return done(e);
    }
  };
  passport.use(
    new LocalStrategy({ usernameField: "email" }, authenticate_user)
  );
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) => done(null, get_user_by_id(id)));
};

module.exports = initialize;
