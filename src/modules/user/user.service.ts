import * as bcrypt from 'bcrypt';
import { And, Between, IsNull, LessThan, Not, Repository } from 'typeorm';
import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '@models/User.entity';
import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';
import { UpdateFirstDataDto } from './dto/first-data.dto';
import { UpdateSecondDataDto } from './dto/second-data.dto';
import { AddressDto } from './dto/address.dto';
import { updateUserDataDto } from './dto/update-user-data.dto';

@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly mailerService: MailerService,
    private readonly configService: ConfigService,
  ) {}

  // Used in loadDataByDefault
  async createUserAdmin(user: Partial<User>): Promise<User> {
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(user.password, salt);

    const newUser = new User();
    newUser.email = user.email as string;
    newUser.password = hashedPassword;
    newUser.email_code = user.email_code as string;
    newUser.email_verified = user.email_verified as boolean;
    const savedUser = await this.userRepository.save(newUser);
    return savedUser;
  }

  async createUser(email: string, password: string): Promise<User> {
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);

    const randomNumber = Math.floor(Math.random() * 100000);
    const emailVerificationCode = randomNumber.toString().padStart(5, '0');

    await this.sendEmail(email, emailVerificationCode);

    const user = new User();
    user.email = email;
    user.password = hashedPassword;
    user.email_code = emailVerificationCode;
    //user.email_code_create_at = Date.now()
    const savedUser = await this.userRepository.save(user);
    return savedUser;
  }

  async save(user: User): Promise<User> {
    return this.userRepository.save(user);
  }

  async sendEmail(email: string, code: string) {
    try {
      await this.mailerService.sendMail({
        to: email,
        from: this.configService.get<string>('nodemailer.from'),
        subject: 'ExpressCash: Codigo de Verificacion',
        template: 'index',
        context: {
          code,
        },
      });
    } catch (error) {
      console.log(error);
    }
  }

  async sendEmailOwner(email: string, code: string, password: string) {
    try {
      await this.mailerService.sendMail({
        to: email,
        from: this.configService.get<string>('nodemailer.from'),
        subject: 'ExpressCash: Verifica tu correo electronico Owner',
        template: 'owner',
        context: {
          code,
          password,
        },
      });
    } catch (error) {
      console.log(error);
    }
  }

  async sendEmailToVerifyMatchResults(email: string, author: string, link: string) {
    try {
      const response = await this.mailerService.sendMail({
        to: email,
        from: this.configService.get<string>('nodemailer.from'),
        subject: `ExpressCash: ${author} ah indicado que participaste de una partida`,
        template: 'verify-match-results',
        context: {
          author,
          link,
        },
      });
      console.log({ response });
    } catch (error) {
      console.log(error);
    }
  }

  async findById(userId: number, select?: (keyof User)[]): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: select,
    });
    if (!user) {
      throw new NotFoundException('El usuario no existe.');
    }
    return user;
  }

  async findByIdWithoutRelations(userId: number): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });
    if (!user) {
      throw new NotFoundException('El usuario no existe.');
    }
    return user;
  }

  async findByIdSocket(userId: number): Promise<User | undefined> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });
    if (!user) {
      return undefined;
    }
    return user;
  }

  async userExistByEmail(email: string): Promise<User | null> {
    const user = await this.userRepository.findOne({ where: { email: email } });
    return user;
  }

  async findByEmailWithPassword(email: string): Promise<User | null> {
    const user = await this.userRepository.createQueryBuilder('user').select('user.password').where('user.email = :email', { email }).getRawOne();

    if (user) return user.user_password;

    return null;
  }

  async updateLastLogin(user: User, token_notifications): Promise<User> {
    user.last_login = new Date();
    user.notification_token = token_notifications;
    return this.userRepository.save(user);
  }

  async changeAvatar(userId: number, avatar: string): Promise<User> {
    const user = await this.findById(userId);
    user.avatar = avatar;
    return this.userRepository.save(user);
  }

  async createWithGoogle(email: string): Promise<User> {
    const password = this.generateRandomPassword();
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User();
    user.email = email;
    user.password = hashedPassword;
    user.email_verified = true;

    const savedUser = await this.userRepository.save(user);

    return savedUser;
  }

  generateRandomPassword(): string {
    const caracteres = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.';
    let password = '';

    for (let i = 0; i < 14; i++) {
      const indice = Math.floor(Math.random() * caracteres.length);
      password += caracteres.charAt(indice);
    }

    password += '@.';

    password = password
      .split('')
      .sort(() => Math.random() - 0.5)
      .join('');

    return password;
  }

  async getUsers(): Promise<User[]> {
    return await this.userRepository.find({
      order: {
        id: 'ASC',
      },
    });
  }

  async getAllUsers(userId: number, data: { first: number; second: number }): Promise<User[]> {
    const response = await this.userRepository.find({
      where: {
        id: Not(userId),
      },
    });
    const slicedResponse = response.slice(data.first, data.second);
    return slicedResponse;
  }

  async verifyEmailCode(code: string, userId: number) {
    const userEmailCode = await this.userRepository.createQueryBuilder('user').select('user.email_code').where('user.id = :id', { id: userId }).getRawOne();
    if (userEmailCode.user_email_code === code) {
      const user = await this.userRepository.findOne({ where: { id: userId } });
      if (!user) {
        throw new NotFoundException('Usuario no encontrado.');
      }
      user.email_verified = true;
      user.email_code = '';
      await this.userRepository.save(user);
      return { ok: true, message: 'Email verificado.' };
    }

    return { ok: false, message: 'El codigo es incorrecto.' };
  }

  async getUsersByIds(userIds: number[]): Promise<User[]> {
    const users = await this.userRepository.find({
      where: userIds.map((id) => ({ id })),
    });
    return users;
  }

  async changePassword(email: string, newPassword): Promise<User> {
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) throw new NotFoundException('Correo electrónico no registrado.');

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    user.email_verified = true;
    user.password = hashedPassword;

    const userSaved = await this.userRepository.save(user);
    return userSaved;
  }

  async updateUser(user: Partial<User>) {
    const dbUser = await this.userRepository.findOne({
      where: {
        email: user.email,
      },
    });

    if (!dbUser) throw new NotFoundException('Correo electrónico no registado');
    for (const property in user) {
      if (property === 'password') {
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(user.password, salt);
        dbUser.password = hashedPassword;
      } else if (user[property]) {
        dbUser[property] = user[property];
      }
    }
    await this.userRepository.update(dbUser.id as number, dbUser);

    return { ok: true, message: 'User updated' };
  }

  async findUserDataById(userId: number): Promise<User | null> {
    const user = await this.findById(userId);
    if (!user) {
      return null;
    }
    return user;
  }

  async updateFirstData(userId: number, updateFirstDataDto: UpdateFirstDataDto) {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });
    if (!user) {
      throw new NotFoundException('El usuario no existe.');
    }
    user.first_name = updateFirstDataDto.first_name;
    user.last_name = updateFirstDataDto.last_name;
    user.cuil = updateFirstDataDto.cuil;
    await this.userRepository.save(user);
    return user;
  }

  formatDateToISO(date: Date): string {
    if (typeof date === 'string') {
      return `${date}`;
    } else {
      const year = date.getFullYear();
      const month = String(date.getMonth() + 1).padStart(2, '0');
      const day = String(date.getDate()).padStart(2, '0');
      return `${year}-${month}-${day}`;
    }
  }

  async updateSecondData(userId: number, updateSecondDataDto: UpdateSecondDataDto) {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });
    if (!user) {
      throw new NotFoundException('El usuario no existe.');
    }
    user.birthday = updateSecondDataDto.birthday;
    user.phone = updateSecondDataDto.phone;

    await this.userRepository.save(user);
    return user;
  }

  async createAddress(userId: number, address: AddressDto) {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });
    if (!user) throw new NotFoundException('El usuario no existe.');

    user.address.push(address);

    await this.userRepository.save(user);
    return user;
  }

  async editAddress(userId: number, addressIndex: number, updateAddress: AddressDto) {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });
    if (!user) throw new NotFoundException('El usuario no existe.');
    if (user.address.length <= addressIndex) throw new NotFoundException('La dirección no existe.');

    user.address[addressIndex] = updateAddress;

    await this.userRepository.save(user);
    return user;
  }

  async deleteAddress(userId: number, addressIndex: number) {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });
    if (!user) throw new NotFoundException('El usuario no existe.');
    if (user.address.length <= addressIndex) throw new NotFoundException('La dirección no existe.');

    user.address.splice(addressIndex, 1);

    await this.userRepository.save(user);
    return user;
  }

  async getAgeStatistics(): Promise<{
    age: {
      age18_30: number;
      age31_45: number;
      age46_60: number;
      age61_over: number;
      total: number;
    };
  }> {
    const currentDate = new Date();

    const date18 = new Date(currentDate.getFullYear() - 18, currentDate.getMonth(), currentDate.getDate());
    const date30 = new Date(currentDate.getFullYear() - 30, currentDate.getMonth(), currentDate.getDate());
    const date45 = new Date(currentDate.getFullYear() - 45, currentDate.getMonth(), currentDate.getDate());
    const date60 = new Date(currentDate.getFullYear() - 60, currentDate.getMonth(), currentDate.getDate());
    const date61 = new Date(currentDate.getFullYear() - 61, currentDate.getMonth(), currentDate.getDate());

    const age18_30 = await this.userRepository.count({
      where: {
        birthday: Between(date30, date18),
      },
    });

    const age31_45 = await this.userRepository.count({
      where: {
        birthday: Between(date45, date30),
      },
    });

    const age46_60 = await this.userRepository.count({
      where: {
        birthday: Between(date60, date45),
      },
    });

    const age61_over = await this.userRepository.count({
      where: {
        birthday: And(Not(IsNull()), LessThan(date61)),
      },
    });

    const total = await this.userRepository.count({
      where: {
        birthday: Not(IsNull()),
      },
    });

    return {
      age: {
        age18_30,
        age31_45,
        age46_60,
        age61_over,
        total,
      },
    };
  }

  async getActiveUsersCountLastWeek(): Promise<number> {
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

    return await this.userRepository.count({
      where: {
        last_login: Between(oneWeekAgo, new Date()),
      },
    });
  }

  async getGenderStats(): Promise<{ female: number; male: number; total: number }> {
    const femaleCount = await this.userRepository.count({
      where: {
        gender: 'female',
      },
    });

    const maleCount = await this.userRepository.count({
      where: {
        gender: 'male',
      },
    });

    const total = femaleCount + maleCount;

    return {
      female: femaleCount,
      male: maleCount,
      total,
    };
  }

  async updateUserData(userId: number, updateUserDataDto: updateUserDataDto): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new NotFoundException('El usuario no existe.');
    }

    user.first_name = updateUserDataDto.first_name;
    user.last_name = updateUserDataDto.last_name;
    user.cuil = updateUserDataDto.cuil;
    user.birthday = updateUserDataDto.birthday;
    user.phone = updateUserDataDto.phone;

    await this.userRepository.save(user);
    return user;
  }
}
