exports.generateOTP=()=>{
    const otp = Math.floor(1000 + Math.random() * 9000);
    console.log(otp.toString());
    return otp.toString();
  }

  