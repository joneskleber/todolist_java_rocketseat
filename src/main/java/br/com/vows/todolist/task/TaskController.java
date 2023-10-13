package br.com.vows.todolist.task;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.vows.todolist.utils.Utils;
import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/tasks")
public class TaskController {

    @Autowired
    private ITaskRepository taskRepository;

    @PostMapping(value = "")
    public ResponseEntity create(@RequestBody TaskModel taskModel, HttpServletRequest request) {
        // System.out.println("Chegou no controller " + request.getAttribute("idUser"));
        var idUser = request.getAttribute("idUser");
        taskModel.setIdUser((UUID) idUser);

        // valida se a data é menor
        var currentDate = LocalDateTime.now();
        if (currentDate.isAfter(taskModel.getStartAt()) || currentDate.isAfter(taskModel.getEndAt())) {
            return ResponseEntity.badRequest()
                    .body("A data de início / data do término deve ser maior que a data atual");
        }

        if (taskModel.getStartAt().isAfter(taskModel.getEndAt())) {
            return ResponseEntity.badRequest()
                    .body("A data do términio de ser maior do que a data de início.");
        }

        var task = this.taskRepository.save(taskModel);
        return ResponseEntity.ok().body(task);
    }

    @GetMapping("")
    public List<TaskModel> list(HttpServletRequest request) {
        var idUser = request.getAttribute("idUser");
        var tasks = this.taskRepository.findByIdUser((UUID) idUser);
        return tasks;
    }

    @PutMapping("/{id}")
    public ResponseEntity update(@RequestBody TaskModel taskModel, @PathVariable UUID id, HttpServletRequest request) {
        // var idUser = request.getAttribute("idUser");

        // taskModel.setIdUser((UUID) idUser);
        // taskModel.setId(id);
        // return this.taskRepository.save(taskModel);

        var task = this.taskRepository.findById(id).orElse(null);

        if (task == null) {
            return ResponseEntity.badRequest().body("Tarefa não encontrada.");
        }

        var idUser = request.getAttribute("idUser");
        if (!task.getIdUser().equals(idUser)) {
            // usuario diferente do dono da tarefa. Retornar error.
            return ResponseEntity.badRequest().body("Usuário não tem permissão para atualizar a tarefa.");
        }

        Utils.copyNonNullProperties(taskModel, task);

        var taskUpdated = this.taskRepository.save(task);

        return ResponseEntity.ok().body(taskUpdated);
    }

}
