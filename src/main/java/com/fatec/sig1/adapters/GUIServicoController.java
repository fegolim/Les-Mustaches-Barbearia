package com.fatec.sig1.adapters;

import javax.validation.Valid;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.fatec.sig1.model.Servico;
import com.fatec.sig1.ports.MantemServico;

@Controller
@RequestMapping(path = "/sig")
public class GUIServicoController {
	Logger logger = LogManager.getLogger(GUIServicoController.class);
	@Autowired
	MantemServico servico;

	@GetMapping("/servicos")
	public ModelAndView retornaFormDeConsultaTodosServicos() {
		ModelAndView modelAndView = new ModelAndView("consultarServico");
		modelAndView.addObject("servicos", servico.consultaTodos());
		return modelAndView;
	}

	@GetMapping("/servico")
	public ModelAndView retornaFormDeCadastroDe(Servico servicoo) {
		ModelAndView mv = new ModelAndView("cadastrarServico");
		mv.addObject("servicos", servicoo);
		return mv;
	}

	@GetMapping("/servicos/{id}") // diz ao metodo que ira responder a uma requisicao do tipo get
	public ModelAndView retornaFormParaEditarServico(@PathVariable("id") Long id) {
		ModelAndView modelAndView = new ModelAndView("atualizarServico");
		modelAndView.addObject("servico", servico.consultaPorId(id).get()); // retorna um objeto do tipo cliente
		return modelAndView; // addObject adiciona objetos para view
	}

	@GetMapping("/servicos/id/{id}")
	public ModelAndView excluirNoFormDeConsultaServico(@PathVariable("id") Long id) {
		servico.delete(id);
		logger.info(">>>>>> 1. servico de exclusao chamado para o id => " + id);
		ModelAndView modelAndView = new ModelAndView("consultarServico");
		modelAndView.addObject("servicos", servico.consultaTodos());
		return modelAndView;
	}

	@PostMapping("/servicos")
	public ModelAndView save(@Valid Servico servicoo, BindingResult result) {
		ModelAndView modelAndView = new ModelAndView("consultarServico");
		if (result.hasErrors()) {
			modelAndView.setViewName("cadastrarServico");
		} else {
			if (servico.save(servicoo).isPresent()) {
				logger.info(">>>>>> controller chamou cadastrar e consulta todos");
				modelAndView.addObject("servicos", servico.consultaTodos());
			} else {
				logger.info(">>>>>> controller cadastrar com dados invalidos");
				modelAndView.setViewName("cadastrarServico");
				modelAndView.addObject("message", "Dados invalidos");
			}
		}
		return modelAndView;
	}

	@PostMapping("/servicos/id/{id}")
	public ModelAndView atualizaServico(@PathVariable("id") Long id, @Valid Servico servicoo, BindingResult result) {
		ModelAndView modelAndView = new ModelAndView("consultarServico");
		logger.info(">>>>>> servico para atualizacao de dados chamado para o id => " + id);
		if (result.hasErrors()) {
			logger.info(">>>>>> servico para atualizacao de dados com erro => " + result.getFieldError().toString());
			((Servico) servico).setId(id);
			return new ModelAndView("atualizarServico");
		} else {
			servico.altera(servicoo);
			modelAndView.addObject("servicos", servico.consultaTodos());
		}
		return modelAndView;
	}
}