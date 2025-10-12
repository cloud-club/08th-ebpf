package util

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	. "ebpf/model"

	"github.com/gofiber/fiber/v2"
)

func PrintData(data Data) {
	if data.ProblemId != "" {
		PrintProblemId(data.ProblemId)
	}
	if data.Code != "" {
		PrintCode(data.Code)
	}
	if data.TimeLimit != 0 || data.MemoryLimit != 0 {
		PrintLimit(data.TimeLimit, data.MemoryLimit)
	}
	if len(data.Inputs) > 0 && len(data.Outputs) > 0 {
		PrintTestcase(data.Inputs, data.Outputs)
	}

	//fmt.Println(data)
}

func PrintProblemId(problemId string) {
	fmt.Println("===ProblemId===")
	fmt.Println(problemId)
	fmt.Println("===============")
	fmt.Println()
}

func PrintCode(code string) {
	fmt.Println("=====Code======")
	fmt.Println(code)
	fmt.Println("===============")
	fmt.Println()
}

func PrintLimit(time, memory int64) {
	fmt.Println("=====Limit=====")
	fmt.Println("Time:   " + strconv.FormatInt(time, 10) + "ms")
	fmt.Println("Memory: " + strconv.FormatInt(memory, 10) + "kb")
	fmt.Println("===============")
	fmt.Println()
}

func PrintTestcase(inputs, outputs []string) {
	fmt.Println("===Testcase====")
	for i := 0; i < len(inputs); i++ {
		fmt.Printf("Input %d:\n%s\n", i+1, inputs[i])
		fmt.Printf("Output %d:\n%s\n", i+1, outputs[i])
		if i < len(inputs)-1 {
			fmt.Println("---")
		}
	}
	fmt.Println("===============")
	fmt.Println()
}

func DecodeBase64(code string) (string, error) {
	decodedCodeByte, err := base64.StdEncoding.DecodeString(code)
	if err != nil {
		return "", fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("[Invalid Base64 Input]\n%v", err))
	}

	return string(decodedCodeByte), nil
}

func GetDataByProblemId(problemId string) (Data, error) {
	data := Data{ProblemId: problemId}

	// limit 폴더 경로 확인
	limitPath := fmt.Sprintf("limit/%s", problemId)
	_, err := os.Stat(limitPath)
	if os.IsNotExist(err) {
		return Data{}, fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("[ProblemId Check Failed]\nLimit folder for problemId %s does not exist", problemId))
	}
	if err != nil {
		return Data{}, fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("[ProblemId Check Failed]\nError checking limit folder for problemId %s\n%v", problemId, err))
	}

	// TimeLimit 읽기
	data.TimeLimit, err = getTimeLimit(problemId)
	if err != nil {
		return Data{}, err
	}

	// MemoryLimit 읽기
	data.MemoryLimit, err = getMemoryLimit(problemId)
	if err != nil {
		return Data{}, err
	}

	// testcase 폴더 경로 확인
	testcasePath := fmt.Sprintf("testcase/%s", problemId)
	_, err = os.Stat(testcasePath)
	if os.IsNotExist(err) {
		return Data{}, fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("[ProblemId Check Failed]\nTestcase folder for problemId %s does not exist", problemId))
	}
	if err != nil {
		return Data{}, fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("[ProblemId Check Failed]\nError checking testcase folder for problemId %s\n%v", problemId, err))
	}

	// Inputs 읽기
	data.Inputs, err = getInputs(problemId)
	if err != nil {
		return Data{}, err
	}

	// Outputs 읽기
	data.Outputs, err = getOutputs(problemId)
	if err != nil {
		return Data{}, err
	}

	return data, nil
}

func getTimeLimit(problemId string) (int64, error) {
	limitPath := fmt.Sprintf("limit/%s", problemId)
	timeLimitPath := fmt.Sprintf("%s/time.txt", limitPath)
	timeLimitBytes, err := os.ReadFile(timeLimitPath)
	if err != nil {
		return 0, fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("[ProblemId Check Failed]\nError reading time.txt for problemId %s\n%v", problemId, err))
	}
	timeLimit, err := strconv.ParseInt(string(timeLimitBytes), 10, 64)
	if err != nil {
		return 0, fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("[ProblemId Check Failed]\nError parsing time limit for problemId %s\n%v", problemId, err))
	}
	return timeLimit, nil
}

func getMemoryLimit(problemId string) (int64, error) {
	limitPath := fmt.Sprintf("limit/%s", problemId)
	memoryLimitPath := fmt.Sprintf("%s/memory.txt", limitPath)
	memoryLimitBytes, err := os.ReadFile(memoryLimitPath)
	if err != nil {
		return 0, fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("[ProblemId Check Failed]\nError reading memory.txt for problemId %s\n%v", problemId, err))
	}
	memoryLimit, err := strconv.ParseInt(string(memoryLimitBytes), 10, 64)
	if err != nil {
		return 0, fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("[ProblemId Check Failed]\nError parsing memory limit for problemId %s\n%v", problemId, err))
	}
	return memoryLimit, nil
}

func getInputs(problemId string) ([]string, error) {
	var inputs []string
	testcasePath := fmt.Sprintf("testcase/%s", problemId)
	inputPath := fmt.Sprintf("%s/in", testcasePath)
	inputFiles, err := os.ReadDir(inputPath)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("[ProblemId Check Failed]\nError reading input files for problemId %s\n%v", problemId, err))
	}
	for _, file := range inputFiles {
		if !file.IsDir() {
			content, err := os.ReadFile(fmt.Sprintf("%s/%s", inputPath, file.Name()))
			if err != nil {
				return nil, fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("[ProblemId Check Failed]\nError reading input file %s for problemId %s\n%v", file.Name(), problemId, err))
			}
			inputs = append(inputs, string(content))
		}
	}
	return inputs, nil
}

func getOutputs(problemId string) ([]string, error) {
	var outputs []string
	testcasePath := fmt.Sprintf("testcase/%s", problemId)
	outputPath := fmt.Sprintf("%s/out", testcasePath)
	outputFiles, err := os.ReadDir(outputPath)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("[ProblemId Check Failed]\nError reading output files for problemId %s\n%v", problemId, err))
	}
	for _, file := range outputFiles {
		if !file.IsDir() {
			content, err := os.ReadFile(fmt.Sprintf("%s/%s", outputPath, file.Name()))
			if err != nil {
				return nil, fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("[ProblemId Check Failed]\nError reading output file %s for problemId %s\n%v", file.Name(), problemId, err))
			}
			outputs = append(outputs, string(content))
		}
	}
	return outputs, nil
}
