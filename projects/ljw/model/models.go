package model

type Data struct {
	ProblemId   string
	Code        string
	TimeLimit   int64
	MemoryLimit int64
	Inputs      []string
	Outputs     []string
}

type Request struct {
	ProblemId string
	Code      string
}

type Response struct {
	Status     string `json:"status"`
	UsedTime   int64  `json:"usedTime"`
	UsedMemory int64  `json:"usedMemory"`
}

type JudgeResult struct {
	Status     JudgeStatusEnum `json:"status"`
	UsedTime   int64           `json:"usedTime"`
	UsedMemory int64           `json:"usedMemory"`
}

type JudgeStatusEnum string

const (
	JudgeCorrect      JudgeStatusEnum = "Correct"
	JudgeWrong        JudgeStatusEnum = "Wrong"
	JudgeTimeOut      JudgeStatusEnum = "Time Out"
	JudgeRuntimeError JudgeStatusEnum = "Runtime Error"
	JudgeCompileError JudgeStatusEnum = "Compile Error"
)
