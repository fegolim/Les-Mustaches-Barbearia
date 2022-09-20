package com.fatec.sig1.ports;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.fatec.sig1.model.Servico;

@Repository
public interface ServicoRepository extends JpaRepository<Servico, Long> {
	Optional<Servico> findById(String id);

	List<Servico> findAllByNomeIgnoreCaseContaining(String nome);
	
}

