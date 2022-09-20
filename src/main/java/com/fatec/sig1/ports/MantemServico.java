package com.fatec.sig1.ports;

import java.util.List;
import java.util.Optional;
import com.fatec.sig1.model.Servico;

public interface MantemServico {
	List<Servico> consultaTodos();

	Optional<Servico> consultaPorNome(String nome);

	Optional<Servico> consultaPorId(Long id);

	Optional<Servico> save(Servico servico);

	void delete(Long id);

	Optional<Servico> altera(Servico servico);
}