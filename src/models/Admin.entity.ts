import { Index, OneToMany } from 'typeorm';
import { Column, Entity } from 'typeorm';
import { BaseEntity } from './Base.entity';
import { SessionAdmin } from './SessionAdmin.entity';

export enum RoleAdminType {
  ADMIN = 'admin',
  SUPER_ADMIN = 'super_admin',
}

@Entity({ name: 'Admins' })
export class Admin extends BaseEntity {
  @Index({ unique: true })
  @Column({ type: 'varchar', length: 255, nullable: false })
  email: string;

  @Column({ type: 'boolean', default: false })
  email_verified: boolean;

  @Column({ type: 'varchar', length: 255, nullable: true })
  full_name: string;

  @Column({ type: 'varchar', length: 255 })
  email_code: string;

  @Column({ type: 'varchar', length: 255, default: 'default-user-avatar.png' })
  avatar: string;

  @Column({ type: 'varchar', length: 128, nullable: false, select: false })
  password: string;

  @Column({ type: 'timestamp', nullable: true })
  last_login?: Date;

  @Column({ type: 'enum', enum: RoleAdminType, default: RoleAdminType.ADMIN })
  role: RoleAdminType;

  // -------- Relations ---------
  @OneToMany(() => SessionAdmin, (sessionAdmin) => sessionAdmin.admin)
  sessionAdmins: SessionAdmin[];
}
