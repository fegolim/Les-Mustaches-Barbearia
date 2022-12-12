package com.fatec.sig1.adapters;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class GUIMenuController {
	@PreAuthorize("hasAnyRole('ADMIN', 'VEND', 'OUTROS')") //FERNANDA
	@GetMapping("/login")
	public ModelAndView autenticacao() {
		return new ModelAndView("paginaLogin");
	}

	//@PreAuthorize("hasRole('OUTROS')") //FERNANDA
	@PreAuthorize("hasAnyRole('ADMIN', 'VEND', 'OUTROS')") //FERNANDA
	@GetMapping("/")
	public ModelAndView home() {
		// return new ModelAndView("paginaMenu");
		return new ModelAndView("index");

	}
}