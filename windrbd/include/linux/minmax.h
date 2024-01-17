#ifndef _MINMAX_H
#define _MINMAX_H

#define min_t(_type, _x, _y)		((_type)_x < (_type)_y ? (_type)_x : (_type)_y)
#define max_t(_type, _x, _y)		((_type)_x < (_type)_y ? (_type)_y : (_type)_x)

#endif
