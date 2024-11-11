import { JoinColumn, ManyToOne } from 'typeorm';
import { Column, Entity } from 'typeorm';
import { BaseEntity } from './Base.entity';
import { Admin } from './Admin.entity';

@Entity({ name: 'SessionAdmins' })
export class SessionAdmin extends BaseEntity {
  @Column()
  expiredAt: Date;

  @Column()
  ip: string;

  @Column()
  browser: string;

  @Column()
  operatingSystem: string;

  @ManyToOne(() => Admin, { eager: true })
  @JoinColumn({ name: 'adminId' })
  admin: Admin;
}
