package com.fatec.sig1.services;

import java.util.List;
import java.util.Optional;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Service;

import com.fatec.sig1.model.Servico;
import com.fatec.sig1.ports.MantemServico;
import com.fatec.sig1.ports.ServicoRepository;

@Service	
public class MantemServicoI implements MantemServico {	
Logger logger = LogManager.getLogger(this.getClass());	
@Autowired	
ServicoRepository repository;	
@Override	
public List<Servico> consultaTodos() {	
	logger.info(">>>>>> servico consultaTodos chamado");	
	return repository.findAll();	
}	
@Override	
public Optional<Servico> consultaPorId(Long id) {	
	logger.info(">>>>>> servico consultaPorId chamado");	
	return repository.findById(id);	
}	
@Override	
public Optional<Servico> save(Servico servico) {
	//produto.getId()
	logger.info(">>>>>> servico save chamado ");	
	return Optional.ofNullable(repository.save(servico));	
}	
@Override	
public void delete(Long id) {	
	logger.info(">>>>>> servico delete por id chamado");	
	repository.deleteById(id);	
}	
@Override	
public Optional<Servico> altera(Servico servico) {	
	logger.info(">>>>>> 1.servico altera produto chamado");	
	Optional<Servico> umServico = consultaPorId(servico.getId());	
	if (umServico.isPresent()) {	
		//Long id, @NotBlank(message = "Nome é requerido") String nome, long codBarras, String marca,
		//String descricao, int qtdEstoque, Double preco
		Servico servicoModificado = new Servico(servico.getId(), servico.getNome(), servico.getDescricao(), servico.getDuracao(), servico.getPreco(), servico.getCategoria());	
		servicoModificado.setId(servico.getId());	
		servicoModificado.setPreco(servico.getPreco());	
			
		return Optional.ofNullable(repository.save(servicoModificado));	
	} else {	
		return Optional.empty();	
	}	
}	
@Override	
public Optional<Servico> consultaPorNome(String nome) {	
	// TODO Auto-generated method stub	
	return null;	
}	
}