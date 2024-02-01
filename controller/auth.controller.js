import User from "../model/user.model.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import createError from "../utils/createError.js";


//register
export const register = async (req, res, next) => {
  try {
    const hashPassword = bcrypt.hashSync(req.body.password, 10);

    const newUser = new User({
      ...req.body,
      password: hashPassword,
      otp: otpCode,
    });

    const savedUser = await newUser.save();
    res.status(200).send(savedUser);
  } catch (err) {
    next(err);
  }
};

//verify user's email
export const verifyEmail = async (req,res,next) => {
  try {
    const otpCode = req.body.otp;
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return next(createError(400,"User not found!!"))
    }

    const storedOTP = user.otp;

    if (otpCode !== storedOTP) {
      return res.status(401).json({ message: 'Invalid OTP' });
    }

    user.verified = true;
    await user.save();

    return res.status(200).json({ message: 'User verified successfully' });

  } catch (err) {
    next(err)
  }
}

//login
export const login = async (req, res, next) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    if (!user) return next(createError(404, "Username doesnt exists!"));

    const matchPassword = bcrypt.compareSync(req.body.password, user.password);
    if (!matchPassword) return next(createError(400, "Password doesnt match!"));

    const token = jwt.sign(
      {
        id: user._id,
        isSeller: user.isSeller,
        isAdmin: user.isAdmin,
      },
      process.env.JWT_KEY
    );

    const { password, ...others } = user._doc;

    res
      .cookie("accessToken", token, {
        secure: true,
        sameSite: 'none'
      })
      .status(200)
      .send(others);
  } catch (err) {
    next(err);
  }
};

//logout
export const logout = async (req, res) => {
  res
    .clearCookie("accessToken", {
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      secure: true,
    })
    .status(200)
    .send("User has been logged out!");
};
