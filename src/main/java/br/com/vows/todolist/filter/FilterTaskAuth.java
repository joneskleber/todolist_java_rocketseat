package br.com.vows.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.vows.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component

public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // valida se a requisição é na rota /tasks
        var serverletPath = request.getServletPath();
        if (!serverletPath.startsWith("/tasks")) {
            filterChain.doFilter(request, response);
            return;
        }

        var authorization = request.getHeader("Authorization");

        var authEncoded = authorization.substring("Basic".length()).trim();

        byte[] authDecode = Base64.getDecoder().decode(authEncoded);

        var authString = new String(authDecode);

        String[] credencials = authString.split(":");

        var username = credencials[0];
        var password = credencials[1];

        // Verifica se o usuário existe no banco de dados
        var user = this.userRepository.findByUsername(username);
        if (user == null) {
            response.sendError(401, "Usuário não encontrado");
            return;
        }

        // Valida se a senha está correta
        var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
        if (!passwordVerify.verified) {
            response.sendError(401, "Senha incorreta");
            return;
        }

        // envia os dados do usuário junto com o request
        request.setAttribute("idUser", user.getId());
        filterChain.doFilter(request, response);
    }
}

// public class FilterTaskAuth implements Filter {

// @Override
// public void doFilter(ServletRequest request, ServletResponse response,
// FilterChain chain)
// throws IOException, ServletException {

// System.out.println("Chegou no filtro");
// chain.doFilter(request, response);
// }

// }
