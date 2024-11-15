import dotenv from 'dotenv';
import express from 'express';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';

dotenv.config();

const prismaClient = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET
const userRouter = express.Router();

const signUpSchema = z.object({
    name     : z.string(),
    email    : z.string().email(),
    password : z.string()
})
const loginSchema = z.object({
    email    : z.string().email(),
    password : z.string()
})

userRouter.post('/signup', async (req:any, res:any) => {
    const { name, email, password } = req.body;
    const {success} = signUpSchema.safeParse({name, email, password})
    if(!success){
        res.json({
            error : "Incorrect Email or Password"
        })
    }

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required.'});
    }

    try {
        const existingUser = await prismaClient.user.findUnique({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already in use.' });
        }
        const newUser = await prismaClient.user.create({
            data: {
                name,
                email,
                password, 
            },
        });
        const token = jwt.sign({ userId: newUser.password }, JWT_SECRET , { expiresIn: '72h' });

        res.status(201).json({ token, user: { id: newUser.id, email: newUser.email, name: newUser.name } });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }
});


userRouter.post('/login', async (req: any, res: any) => {
    const { email, password } = req.body;
  
    const { success } = loginSchema.safeParse({ email, password });
  
    if (!success) {
      return res.status(400).json({
        error: "Incorrect email or password format",
      });
    }

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required.' });
    }
  
    try {
      const user = await prismaClient.user.findUnique({ where: { email } });
  
      if (!user) {
        return res.status(400).json({ error: 'User not found.' });
      }
      jwt.verify(user.password, JWT_SECRET, (err : any) => {
        if (err) {
          return res.status(400).json({ error: 'Invalid credentials.' });
        }

        return res.status(200).json({
          user: { id: user.id, email: user.email, name: user.name }
        });
      });
    } catch (error) {
      console.error('Login error:', error);
      return res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }
  });
  


module.exports = userRouter;
