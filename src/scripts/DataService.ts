import { Injectable, Logger } from '@nestjs/common';
import { UserService } from '../modules/user/user.service';
import { AdminService } from '../modules/admin/admin.service';

@Injectable()
export class DataService {
  private readonly logger = new Logger(DataService.name);
  constructor(
    private readonly userService: UserService,
    private readonly adminService: AdminService,
  ) {}

  async loadDataByDefault(): Promise<void> {
    const defaultUsers = [
      {
        email: 'karlosagreda@hotmail.com',
        password: '123456',
        first_name: 'Carlos',
        email_verified: true,
        email_code: '12345',
      },
      {
        email: 'joseleonardoagreda@gmail.com',
        password: '123456',
        first_name: 'Leonardo',
        email_verified: true,
        email_code: '12345',
      },
      {
        email: 'garciadelriotomas@gmail.com',
        password: '123456',
        first_name: 'Tomas',
        email_verified: true,
        email_code: '12345',
      },
      {
        email: 'alexisfajian@gmail.com',
        password: '123456',
        first_name: 'Alexis',
        email_verified: true,
        email_code: '12345',
      },
      {
        email: 'carreirafranco@gmail.com',
        first_name: 'Franco',
        password: '123456',
        email_verified: true,
        email_code: '12345',
      },
      {
        email: 'Douglasgrl27@gmail.com',
        first_name: 'Douglas',
        password: '123456',
        email_verified: true,
        email_code: '12345',
      },
    ];
    for (const user of defaultUsers) {
      this.logger.debug(`creating default user ${user.email} if it does not exist`);
      const userExists = await this.userService.userExistByEmail(user.email);

      if (!userExists) {
        await this.userService.createUserAdmin(user);
      } else {
        await this.userService.updateUser(user);
      }
    }
    const defaultAdmins = [
      {
        email: 'karlosagreda@hotmail.com',
        password: '123456',
        email_verified: true,
        email_code: '12345',
      },
      {
        email: 'joseleonardoagreda@gmail.com',
        password: '123456',
        email_verified: true,
        email_code: '12345',
      },
      {
        email: 'garciadelriotomas@gmail.com',
        password: '123456',
        email_verified: true,
        email_code: '12345',
      },
      {
        email: 'alexisfajian@gmail.com',
        password: '123456',
        email_verified: true,
        email_code: '12345',
      },
      {
        email: 'douglasgrl27@gmail.com',
        password: '123456',
        email_verified: true,
        email_code: '12345',
      },
    ];
    for (const admin of defaultAdmins) {
      this.logger.debug(`creating default admin ${admin.email} if it does not exist`);
      const AdminExists = await this.adminService.adminExistByEmail(admin.email);

      if (!AdminExists) {
        await this.adminService.createAdmin(admin);
      }
    }
  }
}
