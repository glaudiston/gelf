#include "./map.c"
int colormap_size=6;
struct color_set{
	unsigned char key[50];
	unsigned char value[50];
} color_list[6] = {
};
struct color_set *color_map;

map colormap;
void init_colormap(){
	colormap = map_new();
	map_put(&colormap,"prefix", MAP_KEY_SIZE_AUTO, "\033[38;2;100;44;130m");
	map_put(&colormap,"opcode", MAP_KEY_SIZE_AUTO, "\033[38;2;0;120;135m");
	map_put(&colormap,"modrm", MAP_KEY_SIZE_AUTO, "\033[38;2;140;44;130m");
	map_put(&colormap,"sib", MAP_KEY_SIZE_AUTO, "\033[38;2;200;44;130m");
	map_put(&colormap,"displacement",MAP_KEY_SIZE_AUTO,"\033[38;2;50;70;80m");
	map_put(&colormap,"immediate",MAP_KEY_SIZE_AUTO, "\033[38;2;50;40;100m");
	map_put(&colormap,"REX",MAP_KEY_SIZE_AUTO,"\033[38;2;100;44;130m");
	map_put(&colormap,"jmp",MAP_KEY_SIZE_AUTO,"\033[38;2;0;120;135m");
	map_put(&colormap,"mov",MAP_KEY_SIZE_AUTO,"\033[38;2;0;120;135m");
	map_put(&colormap,"add",MAP_KEY_SIZE_AUTO,"\033[38;2;0;120;135m");
	map_put(&colormap,"imm8",MAP_KEY_SIZE_AUTO,"\033[38;2;50;100;80m");
	map_put(&colormap,"imm32",MAP_KEY_SIZE_AUTO,"\033[38;2;50;100;80m");
	map_put(&colormap,"int",MAP_KEY_SIZE_AUTO,"\033[38;2;50;140;80m");
	map_put(&colormap,"white",MAP_KEY_SIZE_AUTO,"\033[38;2;255;255;255;m");
	map_put(&colormap,"gray",MAP_KEY_SIZE_AUTO,"\033[38;2;100;100;100;m");
}

unsigned char *get_color(unsigned char *item)
{
	if (!cmd_options.show_colors){
		return "";
	}
	char *color = map_get(&colormap,item,MAP_KEY_SIZE_AUTO);
	if (color) {
		return color;
	}
	return "\033[0m";
}
