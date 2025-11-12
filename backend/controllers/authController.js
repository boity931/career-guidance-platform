const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, auth } = require('../config/firebase');
const { sendVerificationEmail } = require('../utils/emailService');
const { generateVerificationCode } = require('../utils/helpers');

// User registration
const register = async (req, res) => {
  try {
    const { email, password, name, role, additionalData } = req.body;
    console.log(`📝 Registration attempt: ${email} as ${role}`);

    // Check if user already exists
    const existingUser = await db.collection('users').where('email', '==', email).get();
    if (!existingUser.empty) {
      return res.status(400).json({ 
        success: false,
        error: 'User already exists with this email' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate verification code
    const verificationCode = generateVerificationCode();

    // Create user in Firebase Auth
    let userRecord;
    try {
      userRecord = await auth.createUser({
        email,
        password: hashedPassword,
        displayName: name,
        emailVerified: false
      });
    } catch (firebaseError) {
      console.error('❌ Firebase Auth creation error:', firebaseError);
      if (firebaseError.code === 'auth/email-already-exists') {
        return res.status(400).json({ 
          success: false,
          error: 'User already exists with this email' 
        });
      }
      throw firebaseError;
    }

    // Create Firestore user document
    const userData = {
      uid: userRecord.uid,
      email,
      name,
      role,
      password: hashedPassword,
      isVerified: false,
      verificationCode,
      createdAt: new Date(),
      updatedAt: new Date(),
      status: 'active',
      ...additionalData
    };
    await db.collection('users').doc(userRecord.uid).set(userData);

    // Create role-specific document (except admin)
    if (role !== 'admin') {
      const collectionName = role === 'company' ? 'companies' : `${role}s`;
      const roleData = {
        uid: userRecord.uid,
        email,
        name,
        createdAt: new Date(),
        updatedAt: new Date(),
        status: 'approved',
        ...additionalData
      };
      await db.collection(collectionName).doc(userRecord.uid).set(roleData);
    }

    // Send verification email (logs code if email not configured)
    let emailSent = false;
    try {
      emailSent = await sendVerificationEmail(email, verificationCode);
    } catch (emailError) {
      console.log('⚠️ Email sending failed, but registration continues');
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: userRecord.uid, role, email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log(`✅ User registered successfully: ${email}`);
    console.log(`📧 Verification code: ${verificationCode}`);

    res.status(201).json({
      success: true,
      message: 'User registered successfully. Please verify your email.',
      token,
      user: {
        id: userRecord.uid,
        email,
        name,
        role,
        isVerified: false
      },
      verificationCode,
      emailSent
    });

  } catch (error) {
    console.error('❌ Registration error:', error);

    let errorMessage = 'Internal server error during registration';
    let statusCode = 500;

    if (error.code === 'auth/invalid-email') {
      errorMessage = 'Invalid email address';
      statusCode = 400;
    } else if (error.code === 'auth/weak-password') {
      errorMessage = 'Password is too weak';
      statusCode = 400;
    } else if (error.code === 'auth/operation-not-allowed') {
      errorMessage = 'Email/password accounts are not enabled';
      statusCode = 400;
    }

    res.status(statusCode).json({
      success: false,
      error: errorMessage,
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Login, verifyEmail, getProfile, devVerify remain unchanged
// Just make sure module.exports is **clean**:
module.exports = {
  register,
  login,
  verifyEmail,
  getProfile,
  devVerify
};
