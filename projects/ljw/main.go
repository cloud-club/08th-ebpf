package main

import (
	. "ebpf/model"
	. "ebpf/src"
	. "ebpf/util"

	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	app.Post("/submit/:problemId", func(c *fiber.Ctx) error {
		problemId := c.Params("problemId")

		data, err := GetDataByProblemId(problemId)
		if err != nil {
			return err
		}

		request := new(Request)
		if err = c.BodyParser(request); err != nil {
			return err
		}

		data.Code, err = DecodeBase64(request.Code)
		if err != nil {
			return err
		}

		result, err := Submit(data)
		if err != nil {
			return err
		}

		return c.JSON(result)
	})

	app.Listen(":1323")
}
