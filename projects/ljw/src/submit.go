package src

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	. "ebpf/model"
	. "ebpf/util"

	"github.com/gofiber/fiber/v2"
)

func Submit(data Data) (JudgeResult, error) {
	result := JudgeResult{}
	PrintData(data)

	codePath := "out/code.c"
	err := SaveCode(codePath, data.Code)
	if err != nil {
		return result, err
	}

	executePath := "out/execute"
	resultStatus, _ := BuildCode(codePath, executePath)
	if resultStatus == JudgeCompileError {
		return JudgeResult{Status: JudgeCompileError}, nil
	}

	result, err = Judge(data)
	if err != nil {
		return result, err
	}

	return result, nil
}

func SaveCode(codePath, code string) error {
	err := os.WriteFile(codePath, []byte(code), os.ModePerm)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("[Code Save Failed]\nError writing code.c file\n%v", err))
	}
	return nil
}

func BuildCode(codePath, executePath string) (JudgeStatusEnum, error) {
	cmd := exec.Command("gcc", codePath, "-o", executePath, "-O2", "-Wall", "-lm", "-static", "-std=gnu99")

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Code Build Failed]\n%s\n%v\n", string(output), err)
		return JudgeCompileError, nil
	}
	return JudgeCorrect, nil
}

func Judge(data Data) (JudgeResult, error) {
	result := JudgeResult{}
	isWrong := false
	isRuntimeError := false
	var totalUsedTime int64 = 0
	var totalUsedMemory int64 = 0
	testCaseCount := int64(len(data.Inputs))

	for i := 0; i < len(data.Inputs); i++ {
		inputContents := []byte(data.Inputs[i])
		expectedOutput := []byte(data.Outputs[i])

		runCmd := []string{"./out/execute"}
		execResult, actualOutput, usedTime, usedMemory, err := executeProgram(runCmd, inputContents, data.TimeLimit, data.MemoryLimit, i+1)
		if execResult == JudgeTimeOut {
			result.Status = JudgeTimeOut
			return result, nil
		}

		if err != nil {
			if execResult == JudgeRuntimeError {
				isRuntimeError = true
			}
			continue
		}

		if !checkDifference(actualOutput, expectedOutput) {
			isWrong = true
		}

		fmt.Printf("사용 시간: %dms\n", usedTime)
		fmt.Printf("사용 메모리: %dkb\n", 0)

		totalUsedTime += usedTime
		totalUsedMemory += usedMemory
	}

	if isRuntimeError {
		result.Status = JudgeRuntimeError
		return result, nil
	}

	result.UsedTime = totalUsedTime / testCaseCount
	result.UsedMemory = totalUsedMemory / testCaseCount

	if isWrong {
		result.Status = JudgeWrong
		return result, nil
	}

	result.Status = JudgeCorrect
	return result, nil
}

func executeProgram(runCmd []string, inputContents []byte, timeLimit, memoryLimit int64, testCaseNum int) (JudgeStatusEnum, []byte, int64, int64, error) {
	fmt.Printf("=====%d번 테스트케이스 실행 중=====\n", testCaseNum)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeLimit)*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, runCmd[0], runCmd[1:]...)
	cmd.Stdin = bytes.NewReader(inputContents)

	var outputBuffer bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		fmt.Println(err)
		return JudgeRuntimeError, nil, 0, 0, err
	}

	startTime := time.Now()
	err := cmd.Wait()
	usedTime := time.Since(startTime).Milliseconds()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		fmt.Println(ctx.Err().Error())
		return JudgeTimeOut, nil, usedTime, 0, ctx.Err()
	}

	if err != nil {
		runtimeError := fmt.Errorf("\n%w\n%s", err, stderr.String())
		fmt.Println(runtimeError)
		return JudgeRuntimeError, nil, usedTime, 0, err
	}

	if stderr.Len() > 0 {
		runtimeError := fmt.Errorf("\n%s", stderr.String())
		fmt.Println(runtimeError)
		return JudgeRuntimeError, nil, usedTime, 0, errors.New(stderr.String())
	}

	output := outputBuffer.Bytes()

	return JudgeCorrect, output, usedTime, 0, nil
}

func checkDifference(executeContents, outputContents []byte) bool {
	fmt.Println("예상 결과\n", string(outputContents))
	fmt.Println("실제 결과\n", string(executeContents))

	if !bytes.Equal(executeContents, outputContents) {
		fmt.Println("결과가 일치하지 않습니다.")
		return false
	}

	fmt.Println("결과가 일치합니다!")
	return true
}
