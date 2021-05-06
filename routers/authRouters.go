package routers

import (
	"ced-paper/CED-Authentication/controllers"
	"github.com/beego/beego/v2/server/web"
)

func init() {
	web.Router("/test", &controllers.AuthController{}, "get:Test")
	web.Router("/caAuth", &controllers.AuthController{}, "post:CaAuth")
	web.Router("/caAuthBack", &controllers.AuthController{}, "post:CaAuthBack")
	web.Router("/timeTest", &controllers.AuthController{}, "post:TimeTest")
}
