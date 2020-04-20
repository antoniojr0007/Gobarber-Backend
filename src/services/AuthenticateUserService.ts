import { getRepository } from 'typeorm';
import { compareSync } from 'bcryptjs';
import { sign } from 'jsonwebtoken';
import authConfig from '../config/auth';

import User from '../models/User';

interface Request {
  email: string;
  password: string;
}

interface Responce {
  user: User;
  token: string;
}

class AuthenticateUserService {
  public async execute({ email, password }: Request): Promise<Responce> {
    const usersRepository = getRepository(User);

    const user = await usersRepository.findOne({ where: { email } });

    if (!user) {
      throw new Error('Incorect Email/Password combination.');
    }

    const passwordMacthed = compareSync(password, user.password);

    if (!passwordMacthed) {
      throw new Error('Incorect Email/Password combination.');
    }

    const { secret, expiresIn } = authConfig.jwt;

    const token = sign({}, secret, {
      subject: user.id,
      expiresIn,
    });

    return { user, token };
  }
}

export default AuthenticateUserService;
