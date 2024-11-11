import { User } from '@models/User.entity';
import { Converter, Mapper } from 'typevert';
import { UserResponseDTO } from './dto/user-response.dto';

@Mapper({ sourceType: User, targetType: UserResponseDTO }, [
  { source: 'id', target: 'id' },
  { source: 'email', target: 'email' },
  { source: 'avatar', target: 'avatar' },
  { source: 'first_name', target: 'first_name' },
  { source: 'last_name', target: 'last_name' },
])
export class UserMapper extends Converter<User, UserResponseDTO> {}
